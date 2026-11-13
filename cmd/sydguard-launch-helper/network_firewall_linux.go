//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"syscall"
	"time"

	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// The only rule parameters are root-journal-derived and the authenticated,
// prebound sockets. The compiler never accepts caller-supplied expressions.
type managedFirewallPlan struct {
	journal      slotJournal
	dns, gateway uint16
}

func firewallPorts(p networkPlan, l *networkListeners, cookie uint64) (uint16, uint16, error) {
	if l == nil || l.dnsTCP == nil || l.dnsUDP == nil || l.gateway == nil || cookie == 0 || l.namespaceCookie != cookie {
		return 0, 0, errors.New("invalid firewall listeners")
	}
	tcp, ok := l.dnsTCP.Addr().(*net.TCPAddr)
	if !ok || tcp == nil {
		return 0, 0, errors.New("invalid DNS listener")
	}
	udp, ok := l.dnsUDP.LocalAddr().(*net.UDPAddr)
	if !ok || udp == nil || l.dnsUDP.RemoteAddr() != nil {
		return 0, 0, errors.New("invalid DNS socket")
	}
	gateway, ok := l.gateway.Addr().(*net.TCPAddr)
	if !ok || gateway == nil {
		return 0, 0, errors.New("invalid gateway listener")
	}
	if tcp.Port <= 0 || tcp.Port > 65535 || gateway.Port <= 0 || gateway.Port > 65535 || tcp.Port == gateway.Port || tcp.AddrPort().Addr() != p.Host || udp.AddrPort() != tcp.AddrPort() || gateway.AddrPort().Addr() != p.Host {
		return 0, 0, errors.New("firewall listener address mismatch")
	}
	for _, socket := range []syscall.Conn{l.dnsTCP, l.dnsUDP, l.gateway} {
		c, err := networkSocketCookie(socket)
		if err != nil || c != cookie {
			return 0, 0, errors.New("firewall listener namespace mismatch")
		}
	}
	return uint16(tcp.Port), uint16(gateway.Port), nil
}

// installManagedFirewall leaves ambiguous results for the journal's creating
// phase to quarantine. No deletion by name or retry is safe after a send.
// The caller must hold slot.lifecycleMu, as prepareNetwork does during Create.
func installManagedFirewall(ctx context.Context, baseFD int, slot *launchSlot, owner uint32, expected slotJournal, hostFD int, host networkObject, listeners *networkListeners) (networkObject, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if slot == nil {
		return networkObject{}, errors.New("missing firewall slot")
	}
	if err := ctx.Err(); err != nil {
		return networkObject{}, err
	}
	if validateJournal(slot, expected) != nil || expected.Network == nil || expected.Network.State != "creating" || len(expected.Network.Objects) != 2 {
		return networkObject{}, errors.New("invalid firewall journal binding")
	}
	current, exists, err := readJournal(baseFD, slot, owner)
	if err != nil || !exists || !reflect.DeepEqual(current, expected) {
		return networkObject{}, errors.New("stale firewall journal")
	}
	p := generatedNetworkPlan(current)
	fd, pid, err := openManagedNFTSocket(ctx, hostFD, host)
	if err != nil {
		return networkObject{}, err
	}
	defer unix.Close(fd)
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	if err != nil {
		return networkObject{}, err
	}
	dns, gateway, err := firewallPorts(p, listeners, cookie)
	if err != nil {
		return networkObject{}, err
	}
	return commitManagedFirewall(ctx, nativeNFTWire{fd: fd}, pid, managedFirewallPlan{journal: current, dns: dns, gateway: gateway})
}

// The GET is performed only after every create ACK and uses the same pinned
// socket and deadline as the atomic batch.
func commitManagedFirewall(ctx context.Context, wire nftWire, pid uint32, plan managedFirewallPlan) (networkObject, error) {
	p := generatedNetworkPlan(plan.journal)
	batch, err := compileManagedFirewall(plan)
	if err != nil {
		return networkObject{}, err
	}
	if _, err = exchangeNFTWire(ctx, wire, pid, batch, 1); err != nil {
		return networkObject{}, err
	}
	req, err := managedNFTGetMessage(p.Table)
	if err != nil {
		return networkObject{}, errors.Join(nftOutcomeUnknown, err)
	}
	reply, err := exchangeNFTWire(ctx, wire, pid, []netlink.Message{req}, 0)
	if err != nil {
		return networkObject{}, errors.Join(nftOutcomeUnknown, err)
	}
	handle, err := managedNFTTableHandle(reply, p.Table)
	if err != nil {
		return networkObject{}, errors.Join(nftOutcomeUnknown, err)
	}
	if err := ctx.Err(); err != nil {
		return networkObject{}, errors.Join(nftOutcomeUnknown, err)
	}
	return networkObject{Kind: "firewall", Handle: handle}, nil

}

func nftU32(v uint32) []byte  { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
func nftPort(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }
func nftMessage(kind uint16, flags netlink.HeaderFlags, attrs []netlink.Attribute) (netlink.Message, error) {
	b, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return netlink.Message{}, err
	}
	return netlink.Message{Header: netlink.Header{Type: netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | kind), Flags: flags}, Data: append([]byte{managedNFTFamily, 0, 0, 0}, b...)}, nil
}
func nftChain(table, name, kind string, hook uint32, priority int32) (netlink.Message, error) {
	h, err := netlink.MarshalAttributes([]netlink.Attribute{{Type: unix.NFTA_HOOK_HOOKNUM, Data: nftU32(hook)}, {Type: unix.NFTA_HOOK_PRIORITY, Data: nftU32(uint32(priority))}})
	if err != nil {
		return netlink.Message{}, err
	}
	return nftMessage(unix.NFT_MSG_NEWCHAIN, netlink.Request|netlink.Acknowledge|netlink.Create|netlink.Excl, []netlink.Attribute{{Type: unix.NFTA_CHAIN_TABLE, Data: []byte(table + "\x00")}, {Type: unix.NFTA_CHAIN_NAME, Data: []byte(name + "\x00")}, {Type: unix.NFTA_CHAIN_TYPE, Data: []byte(kind + "\x00")}, {Type: unix.NFTA_CHAIN_HOOK | unix.NLA_F_NESTED, Data: h}, {Type: unix.NFTA_CHAIN_POLICY, Data: nftU32(1)}})
}
func nftRule(table, chain string, expressions []expr.Any) (netlink.Message, error) {
	var list []netlink.Attribute
	for _, e := range expressions {
		b, err := expr.Marshal(managedNFTFamily, e)
		if err != nil {
			return netlink.Message{}, err
		}
		list = append(list, netlink.Attribute{Type: unix.NFTA_LIST_ELEM | unix.NLA_F_NESTED, Data: b})
	}
	b, err := netlink.MarshalAttributes(list)
	if err != nil {
		return netlink.Message{}, err
	}
	return nftMessage(unix.NFT_MSG_NEWRULE, netlink.Request|netlink.Acknowledge|netlink.Create|unix.NLM_F_APPEND, []netlink.Attribute{{Type: unix.NFTA_RULE_TABLE, Data: []byte(table + "\x00")}, {Type: unix.NFTA_RULE_CHAIN, Data: []byte(chain + "\x00")}, {Type: unix.NFTA_RULE_EXPRESSIONS | unix.NLA_F_NESTED, Data: b}})
}
func nftMeta(key expr.MetaKey, op expr.CmpOp, value []byte) []expr.Any {
	return []expr.Any{&expr.Meta{Key: key, Register: 1}, &expr.Cmp{Op: op, Register: 1, Data: value}}
}
func nftPayload(base expr.PayloadBase, off, length uint32, op expr.CmpOp, value []byte) []expr.Any {
	return []expr.Any{&expr.Payload{DestRegister: 1, Base: base, Offset: off, Len: length}, &expr.Cmp{Op: op, Register: 1, Data: value}}
}
func nftCT(key expr.CtKey, value []byte) []expr.Any {
	return []expr.Any{&expr.Ct{Register: 1, Key: key, Direction: 0}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: value}}
}
func nftIface(name string) []byte { b := make([]byte, 16); copy(b, name); return b }
func nftAddr(a netip.Addr) []byte { b := a.As4(); return b[:] }
func nftNetworkMask() []expr.Any {
	return []expr.Any{&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: []byte{255, 254, 0, 0}, Xor: []byte{0, 0, 0, 0}}, &expr.Cmp{Register: 1, Op: expr.CmpOpEq, Data: []byte{198, 18, 0, 0}}}
}
func nftAppend(groups ...[]expr.Any) []expr.Any {
	var out []expr.Any
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}
func nftVerdict(v expr.VerdictKind) []expr.Any { return []expr.Any{&expr.Verdict{Kind: v}} }
func nftStateEstablished() []expr.Any {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, expr.CtStateBitESTABLISHED)
	return []expr.Any{&expr.Ct{Register: 1, Key: expr.CtKeySTATE}, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: b, Xor: make([]byte, 4)}, &expr.Cmp{Register: 1, Op: expr.CmpOpNeq, Data: make([]byte, 4)}}
}

func compileManagedFirewall(f managedFirewallPlan) ([]netlink.Message, error) {
	p := generatedNetworkPlan(f.journal)
	if !validManagedNFTName(p.Table) || p.HostLink != "sgh"+p.Table[3:] || !p.Host.Is4() || !p.Agent.Is4() || p.Agent != p.Host.Next() || f.dns == 0 || f.gateway == 0 || f.dns == f.gateway {
		return nil, errors.New("invalid firewall plan")
	}
	var batch []netlink.Message
	batch = append(batch, netlink.Message{Header: netlink.Header{Type: unix.NFNL_MSG_BATCH_BEGIN, Flags: netlink.Request}, Data: []byte{0, 0, 0, unix.NFNL_SUBSYS_NFTABLES}})
	add := func(m netlink.Message, err error) error {
		if err != nil {
			return err
		}
		batch = append(batch, m)
		return nil
	}
	if err := add(nftMessage(unix.NFT_MSG_NEWTABLE, netlink.Request|netlink.Acknowledge|netlink.Create|netlink.Excl, []netlink.Attribute{{Type: unix.NFTA_TABLE_NAME, Data: []byte(p.Table + "\x00")}})); err != nil {
		return nil, err
	}
	for _, c := range []struct {
		name, kind string
		hook       uint32
		priority   int32
	}{{"guard", "filter", unix.NF_INET_PRE_ROUTING, -310}, {"dnat", "nat", unix.NF_INET_PRE_ROUTING, -100}, {"input", "filter", unix.NF_INET_LOCAL_IN, 0}, {"forward", "filter", unix.NF_INET_FORWARD, 0}, {"output", "filter", unix.NF_INET_LOCAL_OUT, 0}} {
		if err := add(nftChain(p.Table, c.name, c.kind, c.hook, c.priority)); err != nil {
			return nil, err
		}
	}
	rule := func(chain string, groups ...[]expr.Any) error {
		return add(nftRule(p.Table, chain, nftAppend(groups...)))
	}
	iif := nftMeta(expr.MetaKeyIIFNAME, expr.CmpOpEq, nftIface(p.HostLink))
	oif := nftMeta(expr.MetaKeyOIFNAME, expr.CmpOpEq, nftIface(p.HostLink))
	ipv4 := nftMeta(expr.MetaKeyNFPROTO, expr.CmpOpEq, []byte{unix.NFPROTO_IPV4})
	src := nftPayload(expr.PayloadBaseNetworkHeader, 12, 4, expr.CmpOpEq, nftAddr(p.Agent))
	dst := nftPayload(expr.PayloadBaseNetworkHeader, 16, 4, expr.CmpOpEq, nftAddr(p.Host))
	if err := rule("guard", iif, nftMeta(expr.MetaKeyNFPROTO, expr.CmpOpNeq, []byte{unix.NFPROTO_IPV4}), nftVerdict(expr.VerdictDrop)); err != nil {
		return nil, err
	}
	if err := rule("guard", iif, ipv4, nftPayload(expr.PayloadBaseNetworkHeader, 12, 4, expr.CmpOpNeq, nftAddr(p.Agent)), nftVerdict(expr.VerdictDrop)); err != nil {
		return nil, err
	}
	for _, flow := range []struct {
		proto byte
		dns   bool
		port  uint16
	}{{unix.IPPROTO_TCP, true, f.dns}, {unix.IPPROTO_UDP, true, f.dns}, {unix.IPPROTO_TCP, false, f.gateway}} {
		proto := nftMeta(expr.MetaKeyL4PROTO, expr.CmpOpEq, []byte{flow.proto})
		var origDest, originalPort []expr.Any
		if flow.dns {
			origDest = dst
			originalPort = nftPayload(expr.PayloadBaseTransportHeader, 2, 2, expr.CmpOpEq, nftPort(53))
		} else {
			origDest = nftAppend([]expr.Any{&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4}}, nftNetworkMask())
		}
		nat := []expr.Any{&expr.Immediate{Register: 1, Data: nftAddr(p.Host)}, &expr.Immediate{Register: 2, Data: nftPort(flow.port)}, &expr.NAT{Type: expr.NATTypeDestNAT, Family: unix.NFPROTO_IPV4, RegAddrMin: 1, RegProtoMin: 2}}
		if err := rule("dnat", iif, ipv4, src, proto, origDest, originalPort, nat); err != nil {
			return nil, err
		}
		// Match the original conntrack tuple as well as the translated packet. A
		// direct packet to a private service port cannot pass merely by port number.
		ctDest := nftCT(expr.CtKeyDST, nftAddr(p.Host))
		ctPort := nftCT(expr.CtKeyPROTODST, nftPort(53))
		if !flow.dns {
			ctDest = nftAppend([]expr.Any{&expr.Ct{Register: 1, Key: expr.CtKeyDST, Direction: 0}}, nftNetworkMask())
			ctPort = nil
		}
		tuple := nftAppend(nftCT(expr.CtKeySRC, nftAddr(p.Agent)), nftCT(expr.CtKeyPROTOCOL, []byte{flow.proto}), ctDest, ctPort)
		translatedPort := nftPayload(expr.PayloadBaseTransportHeader, 2, 2, expr.CmpOpEq, nftPort(flow.port))
		if err := rule("input", iif, ipv4, src, dst, proto, translatedPort, tuple, nftVerdict(expr.VerdictAccept)); err != nil {
			return nil, err
		}
		replySrc := nftPayload(expr.PayloadBaseNetworkHeader, 12, 4, expr.CmpOpEq, nftAddr(p.Host))
		replyDst := nftPayload(expr.PayloadBaseNetworkHeader, 16, 4, expr.CmpOpEq, nftAddr(p.Agent))
		replyPort := nftPayload(expr.PayloadBaseTransportHeader, 0, 2, expr.CmpOpEq, nftPort(flow.port))
		if err := rule("output", oif, ipv4, replySrc, replyDst, proto, replyPort, nftStateEstablished(), tuple, nftVerdict(expr.VerdictAccept)); err != nil {
			return nil, err
		}
	}
	// These private sockets belong to this session even on other interfaces.
	// Only the tuple-bound accepts above may reach them; leave all other host
	// addresses and ports to the host's existing policy.
	for _, endpoint := range []struct {
		proto byte
		port  uint16
	}{{unix.IPPROTO_TCP, f.dns}, {unix.IPPROTO_UDP, f.dns}, {unix.IPPROTO_TCP, f.gateway}} {
		if err := rule("input", ipv4, dst, nftMeta(expr.MetaKeyL4PROTO, expr.CmpOpEq, []byte{endpoint.proto}), nftPayload(expr.PayloadBaseTransportHeader, 2, 2, expr.CmpOpEq, nftPort(endpoint.port)), nftVerdict(expr.VerdictDrop)); err != nil {
			return nil, err
		}
	}
	for _, r := range []struct {
		chain string
		iface []expr.Any
	}{{"input", iif}, {"forward", iif}, {"forward", oif}, {"output", oif}} {
		if err := rule(r.chain, r.iface, nftVerdict(expr.VerdictDrop)); err != nil {
			return nil, err
		}
	}
	batch = append(batch, netlink.Message{Header: netlink.Header{Type: unix.NFNL_MSG_BATCH_END, Flags: netlink.Request}, Data: []byte{0, 0, 0, unix.NFNL_SUBSYS_NFTABLES}})
	return batch, nil
}
