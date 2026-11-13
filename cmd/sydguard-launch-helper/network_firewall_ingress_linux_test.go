//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// This small evaluator exercises the emitted expression sequence, not a
// kernel packet path. Unsupported expressions fail the test instead of being
// interpreted as allowing a packet.
type firewallTestPacket struct {
	iif                      string
	src, dst                 netip.Addr
	proto                    byte
	dport                    uint16
	originalSrc, originalDst netip.Addr
	originalDport            uint16
}

func evaluateFirewallTestChain(t *testing.T, rules [][]expr.Any, p firewallTestPacket) (string, netip.Addr, uint16) {
	t.Helper()
	for _, rule := range rules {
		regs := map[uint32][]byte{}
		matched := true
		for _, item := range rule {
			switch e := item.(type) {
			case *expr.Meta:
				switch e.Key {
				case expr.MetaKeyIIFNAME:
					regs[e.Register] = nftIface(p.iif)
				case expr.MetaKeyNFPROTO:
					regs[e.Register] = []byte{unix.NFPROTO_IPV4}
				case expr.MetaKeyL4PROTO:
					regs[e.Register] = []byte{p.proto}
				default:
					t.Fatalf("unsupported meta key %v", e.Key)
				}
			case *expr.Payload:
				switch {
				case e.Base == expr.PayloadBaseNetworkHeader && e.Offset == 12 && e.Len == 4:
					regs[e.DestRegister] = nftAddr(p.src)
				case e.Base == expr.PayloadBaseNetworkHeader && e.Offset == 16 && e.Len == 4:
					regs[e.DestRegister] = nftAddr(p.dst)
				case e.Base == expr.PayloadBaseTransportHeader && e.Offset == 2 && e.Len == 2:
					regs[e.DestRegister] = nftPort(p.dport)
				default:
					t.Fatalf("unsupported payload %+v", e)
				}
			case *expr.Ct:
				if e.Direction != 0 {
					t.Fatalf("unexpected conntrack direction %d", e.Direction)
				}
				switch e.Key {
				case expr.CtKeySRC:
					regs[e.Register] = nftAddr(p.originalSrc)
				case expr.CtKeyDST:
					regs[e.Register] = nftAddr(p.originalDst)
				case expr.CtKeyPROTOCOL:
					regs[e.Register] = []byte{p.proto}
				case expr.CtKeyPROTODST:
					regs[e.Register] = nftPort(p.originalDport)
				default:
					t.Fatalf("unsupported conntrack key %v", e.Key)
				}
			case *expr.Bitwise:
				value := regs[e.SourceRegister]
				if len(value) != int(e.Len) || len(e.Mask) != len(value) || len(e.Xor) != len(value) {
					t.Fatal("invalid bitwise expression")
				}
				result := make([]byte, len(value))
				for i := range value {
					result[i] = value[i]&e.Mask[i] ^ e.Xor[i]
				}
				regs[e.DestRegister] = result
			case *expr.Cmp:
				equal := bytes.Equal(regs[e.Register], e.Data)
				switch e.Op {
				case expr.CmpOpEq:
					matched = equal
				case expr.CmpOpNeq:
					matched = !equal
				default:
					t.Fatalf("unsupported comparison %v", e.Op)
				}
			case *expr.Immediate:
				regs[e.Register] = e.Data
			case *expr.NAT:
				if e.Type != expr.NATTypeDestNAT || e.Family != unix.NFPROTO_IPV4 || len(regs[e.RegAddrMin]) != 4 || len(regs[e.RegProtoMin]) != 2 {
					t.Fatal("unexpected NAT")
				}
				var addr [4]byte
				copy(addr[:], regs[e.RegAddrMin])
				return "dnat", netip.AddrFrom4(addr), binary.BigEndian.Uint16(regs[e.RegProtoMin])
			case *expr.Verdict:
				switch e.Kind {
				case expr.VerdictAccept:
					return "accept", netip.Addr{}, 0
				case expr.VerdictDrop:
					return "drop", netip.Addr{}, 0
				default:
					t.Fatalf("unexpected verdict %v", e.Kind)
				}
			default:
				t.Fatalf("unsupported expression %T", item)
			}
			if !matched {
				break
			}
		}
	}
	return "none", netip.Addr{}, 0
}

func TestManagedFirewallPrivateEndpointIngress(t *testing.T) {
	plan := managedFirewallPlan{journal: slotJournal{UID: 123, Index: 4, Nonce: "test"}, dns: 34567, gateway: 45678}
	p := generatedNetworkPlan(plan.journal)
	batch, err := compileManagedFirewall(plan)
	if err != nil {
		t.Fatal(err)
	}
	var input, dnat [][]expr.Any
	for _, m := range batch {
		if uint16(m.Header.Type) != unix.NFNL_SUBSYS_NFTABLES<<8|unix.NFT_MSG_NEWRULE {
			continue
		}
		chain, rule := decodeFirewallRule(t, m)
		switch chain {
		case "input":
			input = append(input, rule)
		case "dnat":
			dnat = append(dnat, rule)
		}
	}
	base := firewallTestPacket{iif: "eth0", src: p.Agent, dst: p.Host, proto: unix.IPPROTO_UDP, dport: plan.dns, originalSrc: p.Agent, originalDst: p.Host, originalDport: plan.dns}
	for _, test := range []struct {
		name string
		p    firewallTestPacket
		want string
	}{
		{"spoofed-agent-direct-dns-udp", base, "drop"},
		{"spoofed-agent-direct-dns-tcp", func() firewallTestPacket { q := base; q.proto = unix.IPPROTO_TCP; return q }(), "drop"},
		{"spoofed-agent-direct-gateway", func() firewallTestPacket {
			q := base
			q.proto = unix.IPPROTO_TCP
			q.dport = plan.gateway
			q.originalDport = plan.gateway
			return q
		}(), "drop"},
		{"other-interface-original-dns-tuple", func() firewallTestPacket { q := base; q.originalDport = 53; return q }(), "drop"},
		{"other-host-address", func() firewallTestPacket { q := base; q.dst = netip.MustParseAddr("192.0.2.1"); return q }(), "none"},
		{"other-host-port", func() firewallTestPacket { q := base; q.dport = plan.dns + 1; return q }(), "none"},
		{"gateway-udp-is-unrelated", func() firewallTestPacket { q := base; q.dport = plan.gateway; return q }(), "none"},
		{"veth-direct-dns-is-denied", func() firewallTestPacket { q := base; q.iif = p.HostLink; return q }(), "drop"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, _, _ := evaluateFirewallTestChain(t, input, test.p)
			if got != test.want {
				t.Fatalf("got %s, want %s", got, test.want)
			}
		})
	}
	for _, flow := range []struct {
		name           string
		proto          byte
		destination    netip.Addr
		dport, private uint16
	}{
		{"dns-tcp", unix.IPPROTO_TCP, p.Host, 53, plan.dns},
		{"dns-udp", unix.IPPROTO_UDP, p.Host, 53, plan.dns},
		{"gateway-tcp", unix.IPPROTO_TCP, netip.MustParseAddr("198.18.1.2"), 443, plan.gateway},
	} {
		t.Run(flow.name, func(t *testing.T) {
			q := firewallTestPacket{iif: p.HostLink, src: p.Agent, dst: flow.destination, proto: flow.proto, dport: flow.dport, originalSrc: p.Agent, originalDst: flow.destination, originalDport: flow.dport}
			action, host, port := evaluateFirewallTestChain(t, dnat, q)
			if action != "dnat" || host != p.Host || port != flow.private {
				t.Fatalf("DNAT %s %s:%d", action, host, port)
			}
			q.dst, q.dport = host, port
			if got, _, _ := evaluateFirewallTestChain(t, input, q); got != "accept" {
				t.Fatalf("authorized translated flow: %s", got)
			}
		})
	}
}
