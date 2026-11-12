package network

import (
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestTransparentTrustedServiceDialsOnlyDeclaredLoopbackPort(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	addressPort := listener.Addr().(*net.TCPAddr).AddrPort()
	port := addressPort.Port()
	synthetic := NewSynthetic()
	address, err := synthetic.Address("examplelocal-api.sydguard.internal")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewPolicy("")
	if err != nil {
		t.Fatal(err)
	}
	target, err := Canonical("examplelocal-api.sydguard.internal", port)
	if err != nil {
		t.Fatal(err)
	}
	policy.Check("id", "session", target)
	pending := policy.Pending()
	if err = policy.Decide(Decision{pending[0].ID, "allow", "run"}); err != nil {
		t.Fatal(err)
	}
	prior := connectionDestination
	connectionDestination = func(*net.TCPConn) (netip.AddrPort, error) { return netip.AddrPortFrom(address, port), nil }
	defer func() { connectionDestination = prior }()
	gate, err := StartTransparentWithService(synthetic, policy, "id", "session", netip.MustParseAddr("127.0.0.1"), "examplelocal-api.sydguard.internal", port)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := listener.Accept()
		if e == nil {
			defer func() { _ = c.Close() }()
			_, _ = c.Write([]byte("service"))
		}
	}()
	c, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", itoaPort(gate.Address)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	result, err := io.ReadAll(c)
	if err != nil || string(result) != "service" {
		t.Fatalf("service result %q %v", result, err)
	}
	<-done
}
func itoaPort(address string) string { _, port, _ := net.SplitHostPort(address); return port }

func TestTransparentReservedServiceRejectsOtherNamesAndPorts(t *testing.T) {
	synthetic := NewSynthetic()
	policy, err := NewPolicy("")
	if err != nil {
		t.Fatal(err)
	}
	prior := connectionDestination
	var destination atomic.Value
	called := make(chan struct{}, 1)
	connectionDestination = func(*net.TCPConn) (netip.AddrPort, error) {
		value := destination.Load().(netip.AddrPort)
		called <- struct{}{}
		return value, nil
	}
	defer func() { connectionDestination = prior }()
	gate, err := StartTransparentWithService(synthetic, policy, "id", "session", netip.MustParseAddr("127.0.0.1"), "examplelocal-api.sydguard.internal", 1234)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	for _, tc := range []struct {
		host string
		port uint16
	}{{"examplelocal-api.sydguard.internal", 1235}, {"other.sydguard.internal", 1234}, {"sydguard.internal", 1234}} {
		address, err := synthetic.Address(tc.host)
		if err != nil {
			t.Fatal(err)
		}
		target, err := Canonical(tc.host, tc.port)
		if err != nil {
			t.Fatal(err)
		}
		policy.Check("id", "session", target)
		pending := policy.Pending()
		if err := policy.Decide(Decision{pending[0].ID, "allow", "run"}); err != nil {
			t.Fatal(err)
		}
		destination.Store(netip.AddrPortFrom(address, tc.port))
		conn, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", itoaPort(gate.Address)))
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		var b [1]byte
		_, err = conn.Read(b[:])
		<-called
		_ = conn.Close()
		if err != io.EOF {
			t.Fatalf("%s:%d: expected immediate rejection, got %v", tc.host, tc.port, err)
		}
	}
}
