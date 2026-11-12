package network

import (
	"io"
	"net"
	"net/netip"
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
	address, err := synthetic.Address("lambdap-auth.sydguard.internal")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewPolicy("")
	if err != nil {
		t.Fatal(err)
	}
	target, err := Canonical("lambdap-auth.sydguard.internal", port)
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
	gate, err := StartTransparentWithService(synthetic, policy, "id", "session", netip.MustParseAddr("127.0.0.1"), port)
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
