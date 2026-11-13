package network

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func preboundDNS(t *testing.T) (*net.TCPListener, *net.UDPConn) {
	t.Helper()
	tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(tcp.Addr().(*net.TCPAddr).AddrPort()))
	if err != nil {
		_ = tcp.Close()
		t.Fatal(err)
	}
	return tcp, udp
}

func TestDNSPrebound(t *testing.T) {
	tcp, udp := preboundDNS(t)
	synthetic := NewSynthetic()
	dns, err := StartDNSPrebound(synthetic, netip.MustParseAddr("127.0.0.1"), tcp, udp)
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	name := dnsmessage.MustNewName("example.com.")
	request, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 123}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	for _, network := range []string{"udp4", "tcp4"} {
		t.Run(network, func(t *testing.T) {
			c, err := net.Dial(network, dns.Address)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(time.Second))
			packet := request
			if network == "tcp4" {
				packet = append([]byte{byte(len(request) >> 8), byte(len(request))}, request...)
			}
			if _, err := c.Write(packet); err != nil {
				t.Fatal(err)
			}
			var response []byte
			if network == "tcp4" {
				var size [2]byte
				if _, err := io.ReadFull(c, size[:]); err != nil {
					t.Fatal(err)
				}
				response = make([]byte, binary.BigEndian.Uint16(size[:]))
				if _, err := io.ReadFull(c, response); err != nil {
					t.Fatal(err)
				}
			} else {
				response = make([]byte, 4096)
				n, err := c.Read(response)
				if err != nil {
					t.Fatal(err)
				}
				response = response[:n]
			}
			var msg dnsmessage.Message
			if err := msg.Unpack(response); err != nil {
				t.Fatal(err)
			}
			want, ok := synthetic.ExistingAddress("example.com")
			if !ok || msg.Header.ID != 123 || len(msg.Answers) != 1 {
				t.Fatalf("bad response: %+v", msg)
			}
			a, ok := msg.Answers[0].Body.(*dnsmessage.AResource)
			if !ok || netip.AddrFrom4(a.A) != want {
				t.Fatalf("bad DNS answer: %+v", msg.Answers)
			}
		})
	}
}

func TestDNSPreboundRejectsMismatchWithoutTakingOwnership(t *testing.T) {
	tcp, udp := preboundDNS(t)
	defer tcp.Close()
	defer udp.Close()
	other, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := StartDNSPrebound(NewSynthetic(), netip.MustParseAddr("127.0.0.1"), tcp, other); err == nil {
		t.Fatal("accepted mismatched port")
	}
	// Reusing the same TCP socket verifies rejection did not close it.
	dns, err := StartDNSPrebound(NewSynthetic(), netip.MustParseAddr("127.0.0.1"), tcp, udp)
	if err != nil {
		t.Fatal(err)
	}
	dns.Close()
}

func TestPreboundRejectsClosedSockets(t *testing.T) {
	tcp, udp := preboundDNS(t)
	defer udp.Close()
	if err := tcp.Close(); err != nil {
		t.Fatal(err)
	}
	synthetic := NewSynthetic()
	agent := netip.MustParseAddr("127.0.0.1")
	if _, err := StartDNSPrebound(synthetic, agent, tcp, udp); err == nil {
		t.Fatal("accepted closed DNS listener")
	}
	policy, err := NewPolicy("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := StartTransparentPrebound(tcp, synthetic, policy, "s", "work", agent); err == nil {
		t.Fatal("accepted closed gateway listener")
	}
}

func TestTransparentPreboundManagedAdmission(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewPolicy("")
	if err != nil {
		t.Fatal(err)
	}
	mustBind(t, policy, testBinding("s"), networkSnapshot(t, exampleRule))
	synthetic := NewSynthetic()
	address, err := synthetic.Address("example.com")
	if err != nil {
		t.Fatal(err)
	}
	var destination atomic.Value
	destination.Store(netip.AddrPortFrom(address, 443))
	oldDestination, oldDial := connectionDestination, dialVettedPublic
	connectionDestination = func(*net.TCPConn) (netip.AddrPort, error) { return destination.Load().(netip.AddrPort), nil }
	var calls atomic.Int32
	var mixed atomic.Bool
	dialVettedPublic = func(ctx context.Context, target Target) (net.Conn, error) {
		return dialPublicWith(ctx, target, func(context.Context, string, string) ([]netip.Addr, error) {
			addresses := []netip.Addr{netip.MustParseAddr("8.8.8.8")}
			if mixed.Load() {
				addresses = append(addresses, netip.MustParseAddr("127.0.0.1"))
			}
			return addresses, nil
		}, func(_ context.Context, network, address string) (net.Conn, error) {
			calls.Add(1)
			if network != "tcp" || address != "8.8.8.8:443" {
				t.Errorf("unexpected dial %s %s", network, address)
			}
			a, b := net.Pipe()
			go func() { defer b.Close(); _, _ = b.Write([]byte("ok")) }()
			return a, nil
		})
	}
	defer func() { connectionDestination, dialVettedPublic = oldDestination, oldDial }()
	gate, err := StartTransparentPrebound(listener, synthetic, policy, "s", "work", netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	read := func() string {
		t.Helper()
		c, err := net.Dial("tcp4", gate.Address)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		b, err := io.ReadAll(c)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if got := read(); got != "ok" {
		t.Fatalf("approved: %q", got)
	}
	destination.Store(netip.AddrPortFrom(address, 444))
	if got := read(); got != "" {
		t.Fatalf("wrong port: %q", got)
	}
	destination.Store(netip.MustParseAddrPort("8.8.8.8:443"))
	if got := read(); got != "" {
		t.Fatalf("direct IP: %q", got)
	}
	destination.Store(netip.AddrPortFrom(address, 443))
	mixed.Store(true)
	if got := read(); got != "" {
		t.Fatalf("mixed DNS: %q", got)
	}
	if calls.Load() != 1 {
		t.Fatalf("dial count %d", calls.Load())
	}
}
