//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"syscall"
	"testing"

	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func attr(t *testing.T, b []byte, kind uint16) []byte {
	t.Helper()
	as, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range as {
		if a.Type&0x3fff == kind {
			return a.Data
		}
	}
	t.Fatalf("missing attribute %d", kind)
	return nil
}
func decodeFirewallRule(t *testing.T, m netlink.Message) (string, []expr.Any) {
	t.Helper()
	chain := string(attr(t, m.Data[4:], unix.NFTA_RULE_CHAIN))
	chain = chain[:len(chain)-1]
	list := attr(t, m.Data[4:], unix.NFTA_RULE_EXPRESSIONS)
	elems, err := netlink.UnmarshalAttributes(list)
	if err != nil {
		t.Fatal(err)
	}
	var out []expr.Any
	for _, a := range elems {
		if a.Type&0x3fff != unix.NFTA_LIST_ELEM {
			t.Fatal("bad list element")
		}
		name := string(attr(t, a.Data, unix.NFTA_EXPR_NAME))
		data := attr(t, a.Data, unix.NFTA_EXPR_DATA)
		var e expr.Any
		switch name {
		case "meta\x00":
			e = &expr.Meta{}
		case "payload\x00":
			e = &expr.Payload{}
		case "cmp\x00":
			e = &expr.Cmp{}
		case "ct\x00":
			e = &expr.Ct{}
		case "bitwise\x00":
			e = &expr.Bitwise{}
		case "nat\x00":
			e = &expr.NAT{}
		case "immediate\x00":
			if binary.BigEndian.Uint32(attr(t, data, unix.NFTA_IMMEDIATE_DREG)) == 0 {
				e = &expr.Verdict{}
			} else {
				e = &expr.Immediate{}
			}
		default:
			t.Fatalf("unexpected expression %q", name)
		}
		if err := expr.Unmarshal(managedNFTFamily, data, e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return chain, out
}
func TestManagedFirewallCompilerScopedAndExclusive(t *testing.T) {
	j := slotJournal{UID: 123, Index: 4, Nonce: "test"}
	p := generatedNetworkPlan(j)
	batch, err := compileManagedFirewall(managedFirewallPlan{journal: j, dns: 34567, gateway: 45678})
	if err != nil {
		t.Fatal(err)
	}
	if len(batch) != 26 {
		t.Fatalf("batch length %d", len(batch))
	}
	if batch[0].Header.Type != unix.NFNL_MSG_BATCH_BEGIN || batch[len(batch)-1].Header.Type != unix.NFNL_MSG_BATCH_END {
		t.Fatal("not one atomic batch")
	}
	table := batch[1]
	if table.Header.Type != netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_NEWTABLE) || table.Header.Flags&(netlink.Create|netlink.Excl|netlink.Acknowledge) != (netlink.Create|netlink.Excl|netlink.Acknowledge) || table.Data[0] != managedNFTFamily || string(attr(t, table.Data[4:], unix.NFTA_TABLE_NAME)) != p.Table+"\x00" {
		t.Fatal("table not exclusive and root-derived")
	}
	chains := map[string]int{}
	rules := map[string][][]expr.Any{}
	for i, m := range batch[1 : len(batch)-1] {
		if m.Header.Flags&netlink.Acknowledge == 0 {
			t.Fatalf("message %d lacks ACK", i+1)
		}
		if len(m.Data) < 4 || m.Data[0] != managedNFTFamily {
			t.Fatal("wrong family")
		}
		switch uint16(m.Header.Type) & 0xff {
		case unix.NFT_MSG_NEWTABLE:
		case unix.NFT_MSG_NEWCHAIN:
			name := string(attr(t, m.Data[4:], unix.NFTA_CHAIN_NAME))
			chains[name[:len(name)-1]]++
			if binary.BigEndian.Uint32(attr(t, m.Data[4:], unix.NFTA_CHAIN_POLICY)) != 1 {
				t.Fatal("global DROP policy")
			}
		case unix.NFT_MSG_NEWRULE:
			chain, es := decodeFirewallRule(t, m)
			rules[chain] = append(rules[chain], es)
		default:
			t.Fatal("unexpected operation")
		}
	}
	for _, c := range []string{"guard", "dnat", "input", "forward", "output"} {
		if chains[c] != 1 {
			t.Fatalf("missing chain %s", c)
		}
	}
	for chain, n := range map[string]int{"guard": 2, "dnat": 3, "input": 7, "forward": 2, "output": 4} {
		if len(rules[chain]) != n {
			t.Fatalf("wrong %s rule count", chain)
		}
	}
	for _, chain := range []string{"guard", "dnat", "input", "forward", "output"} {
		for i, r := range rules[chain] {
			// Three input drops are instead scoped to private host endpoints.
			if chain == "input" && i >= 3 && i <= 5 {
				continue
			}
			if len(r) < 3 {
				t.Fatal("empty rule")
			}
			m, ok := r[0].(*expr.Meta)
			if !ok || (m.Key != expr.MetaKeyIIFNAME && m.Key != expr.MetaKeyOIFNAME) {
				t.Fatalf("unscoped %s rule", chain)
			}
			c, ok := r[1].(*expr.Cmp)
			if !ok || string(c.Data) != string(nftIface(p.HostLink)) {
				t.Fatalf("wrong interface in %s", chain)
			}
		}
	}
	for _, chain := range []string{"input", "forward", "output"} {
		r := rules[chain][len(rules[chain])-1]
		v, ok := r[len(r)-1].(*expr.Verdict)
		if !ok || v.Kind != expr.VerdictDrop {
			t.Fatalf("%s lacks final scoped drop", chain)
		}
	}
	for _, r := range rules["dnat"] {
		n, ok := r[len(r)-1].(*expr.NAT)
		if !ok || n.Type != expr.NATTypeDestNAT || n.Family != unix.NFPROTO_IPV4 {
			t.Fatal("missing IPv4 DNAT")
		}
	}
	for _, chain := range []string{"input", "output"} {
		for _, r := range rules[chain][:3] {
			haveSrc, haveDst, haveProto, haveState := false, false, false, false
			for _, e := range r {
				if c, ok := e.(*expr.Ct); ok {
					switch c.Key {
					case expr.CtKeySRC:
						haveSrc = true
					case expr.CtKeyDST:
						haveDst = true
					case expr.CtKeyPROTOCOL:
						haveProto = true
					case expr.CtKeySTATE:
						haveState = true
					}
				}
			}
			if !haveSrc || !haveDst || !haveProto || (chain == "output" && !haveState) {
				t.Fatalf("unbound %s tuple", chain)
			}
		}
	}
}
func TestManagedFirewallRejectsInvalidBindings(t *testing.T) {
	j := slotJournal{UID: 1, Index: 1, Nonce: "test"}
	for _, ports := range [][2]uint16{{0, 2}, {2, 0}, {2, 2}} {
		if _, err := compileManagedFirewall(managedFirewallPlan{journal: j, dns: ports[0], gateway: ports[1]}); err == nil {
			t.Fatal("accepted invalid ports")
		}
	}
	if _, _, err := firewallPorts(networkPlan{Host: netip.MustParseAddr("10.1.1.1")}, nil, 1); err == nil {
		t.Fatal("accepted missing listeners")
	}
}

func TestCommitManagedFirewallACKsBeforeHandleLookup(t *testing.T) {
	plan := managedFirewallPlan{journal: slotJournal{UID: 123, Index: 4, Nonce: "test"}, dns: 34567, gateway: 45678}
	batch, err := compileManagedFirewall(plan)
	if err != nil {
		t.Fatal(err)
	}
	var acks [][]byte
	for i, m := range batch {
		if m.Header.Flags&netlink.Acknowledge != 0 {
			acks = append(acks, ackPacket(t, nftAckForTest(m, 123, uint32(i+1), 0)))
		}
	}
	p := generatedNetworkPlan(plan.journal)
	handle := make([]byte, 8)
	binary.BigEndian.PutUint64(handle, 777)
	attrs, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.NFTA_TABLE_NAME, Data: []byte(p.Table + "\x00")}, {Type: nftTableHandle, Data: handle}})
	if err != nil {
		t.Fatal(err)
	}
	reply, err := (netlink.Message{Header: netlink.Header{Length: uint32(unix.NLMSG_HDRLEN + 4 + len(attrs)), Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWTABLE), PID: 123, Sequence: 1}, Data: append([]byte{managedNFTFamily, 0, 0, 0}, attrs...)}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("success", func(t *testing.T) {
		w := &mockNFTWire{packets: append(append([][]byte(nil), acks...), reply)}
		o, err := commitManagedFirewall(context.Background(), w, 123, plan)
		if err != nil || o.Kind != "firewall" || o.Handle != 777 {
			t.Fatalf("object=%+v err=%v", o, err)
		}
		ms, err := syscall.ParseNetlinkMessage(w.sent)
		if err != nil || len(ms) != len(batch)+1 || ms[len(ms)-1].Header.Type != unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_GETTABLE {
			t.Fatalf("missing actual GET: %v %v", ms, err)
		}
	})
	t.Run("missing ACK", func(t *testing.T) {
		w := &mockNFTWire{packets: acks[:len(acks)-1]}
		_, err := commitManagedFirewall(context.Background(), w, 123, plan)
		if !errors.Is(err, nftOutcomeUnknown) {
			t.Fatalf("expected quarantine: %v", err)
		}
		ms, _ := syscall.ParseNetlinkMessage(w.sent)
		if len(ms) != len(batch) {
			t.Fatal("lookup issued before complete ACKs")
		}
	})
	t.Run("missing GET", func(t *testing.T) {
		w := &mockNFTWire{packets: acks}
		_, err := commitManagedFirewall(context.Background(), w, 123, plan)
		if !errors.Is(err, nftOutcomeUnknown) {
			t.Fatalf("expected quarantine: %v", err)
		}
	})
	t.Run("collision", func(t *testing.T) {
		w := &mockNFTWire{packets: [][]byte{ackPacket(t, nftAckForTest(batch[1], 123, 2, -int32(unix.EEXIST)))}}
		_, err := commitManagedFirewall(context.Background(), w, 123, plan)
		if !errors.Is(err, unix.EEXIST) || !errors.Is(err, nftOutcomeUnknown) {
			t.Fatalf("collision not refused: %v", err)
		}
		ms, _ := syscall.ParseNetlinkMessage(w.sent)
		if len(ms) != len(batch) {
			t.Fatal("lookup after collision")
		}
	})
}
