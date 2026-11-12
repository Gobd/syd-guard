package network

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestTransparentLearningRecordsOnlySuccessfulVettedDial(t *testing.T) {
	synthetic := NewSynthetic()
	address, err := synthetic.Address("example.com")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewPolicy("")
	if err != nil {
		t.Fatal(err)
	}
	oldDestination, oldDial := connectionDestination, dialVettedPublic
	defer func() { connectionDestination, dialVettedPublic = oldDestination, oldDial }()
	connectionDestination = func(*net.TCPConn) (netip.AddrPort, error) { return netip.AddrPortFrom(address, 443), nil }
	dialVettedPublic = func(_ context.Context, target Target) (net.Conn, error) {
		if target.Host != "example.com" || target.Port != 443 {
			t.Errorf("wrong target: %+v", target)
		}
		a, b := net.Pipe()
		go func() { defer func() { _ = b.Close() }(); _, _ = b.Write([]byte("ok")) }()
		return a, nil
	}
	gate, err := StartTransparentLearning(synthetic, policy, "id", "name", netip.MustParseAddr("127.0.0.1"), "", 0, true)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", itoaPort(gate.Address)))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	data, err := io.ReadAll(conn)
	_ = conn.Close()
	if err != nil || string(data) != "ok" {
		t.Fatalf("dial result %q: %v", data, err)
	}
	dials, dropped := gate.CloseAndLearningDials()
	if dropped || len(dials) != 1 || dials[0] != (Target{Host: "example.com", Port: 443, Transport: "tcp"}) {
		t.Fatalf("dials=%+v dropped=%v", dials, dropped)
	}
	if len(policy.Pending()) != 0 {
		t.Fatal("learning generated an approval")
	}
}

func TestTransparentLearningCloseCancelsPendingDialWithoutRecording(t *testing.T) {
	synthetic := NewSynthetic()
	address, err := synthetic.Address("example.com")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewPolicy("")
	if err != nil {
		t.Fatal(err)
	}
	oldDestination, oldDial := connectionDestination, dialVettedPublic
	defer func() { connectionDestination, dialVettedPublic = oldDestination, oldDial }()
	connectionDestination = func(*net.TCPConn) (netip.AddrPort, error) { return netip.AddrPortFrom(address, 443), nil }
	started := make(chan struct{})
	dialVettedPublic = func(ctx context.Context, _ Target) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, errors.New("cancelled")
	}
	gate, err := StartTransparentLearning(synthetic, policy, "id", "name", netip.MustParseAddr("127.0.0.1"), "", 0, true)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", itoaPort(gate.Address)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("dial did not start")
	}
	dials, dropped := gate.CloseAndLearningDials()
	if dropped || len(dials) != 0 {
		t.Fatalf("cancelled dial recorded: %+v", dials)
	}
}

func TestTransparentLearningNeverRecordsDNSOrFailedDial(t *testing.T) {
	synthetic := NewSynthetic()
	address, err := synthetic.Address("example.com")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewPolicy("")
	if err != nil {
		t.Fatal(err)
	}
	oldDestination, oldDial := connectionDestination, dialVettedPublic
	defer func() { connectionDestination, dialVettedPublic = oldDestination, oldDial }()
	connectionDestination = func(*net.TCPConn) (netip.AddrPort, error) { return netip.AddrPortFrom(address, 443), nil }
	dialVettedPublic = func(context.Context, Target) (net.Conn, error) { return nil, errors.New("dial failed") }
	gate, err := StartTransparentLearning(synthetic, policy, "id", "name", netip.MustParseAddr("127.0.0.1"), "", 0, true)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", itoaPort(gate.Address)))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	_, err = conn.Read(b[:])
	_ = conn.Close()
	if err != io.EOF {
		t.Fatalf("failed dial not closed: %v", err)
	}
	dials, dropped := gate.CloseAndLearningDials()
	if dropped || len(dials) != 0 {
		t.Fatalf("DNS or failed dial recorded: %+v", dials)
	}
}

func TestTransparentLearningNeverRecordsDeclaredPrivateService(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	port := listener.Addr().(*net.TCPAddr).AddrPort().Port()
	synthetic := NewSynthetic()
	address, err := synthetic.Address("fixture.sydguard.internal")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewPolicy("")
	if err != nil {
		t.Fatal(err)
	}
	prior := connectionDestination
	defer func() { connectionDestination = prior }()
	connectionDestination = func(*net.TCPConn) (netip.AddrPort, error) { return netip.AddrPortFrom(address, port), nil }
	gate, err := StartTransparentLearning(synthetic, policy, "id", "name", netip.MustParseAddr("127.0.0.1"), "fixture.sydguard.internal", port, true)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, e := listener.Accept()
		if e == nil {
			_ = conn.Close()
		}
	}()
	conn, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", itoaPort(gate.Address)))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	_, _ = conn.Read(b[:])
	_ = conn.Close()
	<-done
	dials, dropped := gate.CloseAndLearningDials()
	if dropped || len(dials) != 0 {
		t.Fatalf("private service recorded: %+v", dials)
	}
}
