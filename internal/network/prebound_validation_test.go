package network

import (
	"net"
	"net/netip"
	"testing"
)

func TestPreboundDNSRejectsConnectedAndClosedUDP(t *testing.T) {
	tcp, udp := preboundDNS(t)
	defer tcp.Close()
	addr := udp.LocalAddr().(*net.UDPAddr)
	if err := udp.Close(); err != nil {
		t.Fatal(err)
	}
	connected, err := net.DialUDP("udp4", addr, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53})
	if err != nil {
		t.Fatal(err)
	}
	defer connected.Close()
	agent := netip.MustParseAddr("127.0.0.1")
	if _, err := StartDNSPrebound(NewSynthetic(), agent, tcp, connected); err == nil {
		t.Fatal("accepted connected UDP")
	}
	if !socketOpen(tcp) || !socketOpen(connected) {
		t.Fatal("rejection took ownership")
	}
	if err := connected.Close(); err != nil {
		t.Fatal(err)
	}
	closed, err := net.ListenUDP("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := StartDNSPrebound(NewSynthetic(), agent, tcp, closed); err == nil {
		t.Fatal("accepted closed UDP")
	}
	if !socketOpen(tcp) {
		t.Fatal("rejection closed TCP")
	}
}

func TestPreboundRejectsIPv6AndInvalidArguments(t *testing.T) {
	tcp, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.ParseIP("::1")})
	if err != nil {
		t.Skipf("IPv6 unavailable: %v", err)
	}
	defer tcp.Close()
	udp, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("::1"), Port: tcp.Addr().(*net.TCPAddr).Port})
	if err != nil {
		t.Skipf("IPv6 UDP unavailable: %v", err)
	}
	defer udp.Close()
	agent := netip.MustParseAddr("127.0.0.1")
	if _, err := StartDNSPrebound(NewSynthetic(), agent, tcp, udp); err == nil {
		t.Fatal("accepted IPv6 DNS sockets")
	}
	p, err := NewPolicy("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := StartTransparentPrebound(tcp, NewSynthetic(), p, "session", "name", agent); err == nil {
		t.Fatal("accepted IPv6 gateway")
	}
	if _, err := StartDNSPrebound(nil, agent, tcp, udp); err == nil {
		t.Fatal("accepted nil synthetic map")
	}
	if _, err := StartTransparentPrebound(nil, NewSynthetic(), p, "session", "name", agent); err == nil {
		t.Fatal("accepted nil listener")
	}
	if !socketOpen(tcp) || !socketOpen(udp) {
		t.Fatal("rejection took ownership")
	}
}
