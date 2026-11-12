package network

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

var connectionDestination = originalDestination

// Transparent accepts only the session veth's source address. SO_ORIGINAL_DST
// provides the actual synthetic endpoint/port; hostname is looked up in the
// session-local DNS mapping. No client proxy setting or hostname hint is trusted.
type Transparent struct {
	Address       string
	listener      *net.TCPListener
	synthetic     *Synthetic
	policy        *Policy
	session, name string
	agent         netip.Addr
	mu            sync.Mutex
	connections   map[net.Conn]bool
	slots         chan struct{}
	closed        bool
	servicePort   uint16
	serviceHost   string
}

func StartTransparent(synthetic *Synthetic, policy *Policy, session, name string, agent netip.Addr) (*Transparent, error) {
	return StartTransparentWithService(synthetic, policy, session, name, agent, "", 0)
}

// StartTransparentWithService allows the single explicitly trusted service to be dialed by the gateway.
func StartTransparentWithService(synthetic *Synthetic, policy *Policy, session, name string, agent netip.Addr, serviceHost string, servicePort uint16) (*Transparent, error) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero})
	if err != nil {
		return nil, err
	}
	gate := &Transparent{Address: listener.Addr().String(), listener: listener, synthetic: synthetic, policy: policy, session: session, name: name, agent: agent, connections: map[net.Conn]bool{}, slots: make(chan struct{}, 16), servicePort: servicePort, serviceHost: serviceHost}
	go gate.accept()
	return gate, nil
}

func (g *Transparent) Close() {
	_ = g.listener.Close()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = true
	for conn := range g.connections {
		_ = conn.Close()
	}
	g.policy.End(g.session)
}

func (g *Transparent) accept() {
	for {
		conn, err := g.listener.AcceptTCP()
		if err != nil {
			return
		}
		select {
		case g.slots <- struct{}{}:
			go func() { defer func() { _ = conn.Close(); <-g.slots }(); g.forward(conn) }()
		default:
			_ = conn.Close()
		}
	}
}

func (g *Transparent) forward(conn *net.TCPConn) {
	peer, ok := netip.AddrFromSlice(conn.RemoteAddr().(*net.TCPAddr).IP)
	if !ok || peer.Unmap() != g.agent {
		return
	}
	destination, err := connectionDestination(conn)
	if err != nil {
		return
	}
	host, ok := g.synthetic.Host(destination.Addr())
	if !ok {
		return
	}
	target, err := Canonical(host, destination.Port())
	if ReservedServiceHost(host) && (g.servicePort == 0 || host != g.serviceHost || destination.Port() != g.servicePort) {
		return
	}
	if err != nil || !g.policy.Check(g.session, g.name, target) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var upstream net.Conn
	if target.Host == g.serviceHost && target.Port == g.servicePort && g.servicePort != 0 {
		upstream, err = (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(g.servicePort))))
	} else {
		upstream, err = dialPublic(ctx, target)
	}
	if err != nil {
		return
	}
	defer func() { _ = upstream.Close() }()
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	g.connections[conn] = true
	g.connections[upstream] = true
	g.mu.Unlock()
	defer func() { g.mu.Lock(); delete(g.connections, conn); delete(g.connections, upstream); g.mu.Unlock() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))
	_ = upstream.SetDeadline(time.Now().Add(5 * time.Minute))
	done := make(chan struct{})
	go func() { _, _ = io.Copy(upstream, conn); _ = upstream.Close(); close(done) }()
	_, _ = io.Copy(conn, upstream)
	_ = conn.Close()
	<-done
}

// ReservedServiceHost identifies names that cannot be treated as public targets.
func ReservedServiceHost(host string) bool {
	return host == "sydguard.internal" || strings.HasSuffix(host, ".sydguard.internal")
}
