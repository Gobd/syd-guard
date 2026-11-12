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

var (
	connectionDestination = originalDestination
	dialVettedPublic      = dialPublic
)

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
	learning      bool
	dials         []Target
	dropped       bool
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	closeOnce     sync.Once
	closeDone     chan struct{}
}

func StartTransparent(synthetic *Synthetic, policy *Policy, session, name string, agent netip.Addr) (*Transparent, error) {
	return StartTransparentWithService(synthetic, policy, session, name, agent, "", 0)
}

// StartTransparentWithService allows the single explicitly trusted service to be dialed by the gateway.
func StartTransparentWithService(synthetic *Synthetic, policy *Policy, session, name string, agent netip.Addr, serviceHost string, servicePort uint16) (*Transparent, error) {
	return StartTransparentLearning(synthetic, policy, session, name, agent, serviceHost, servicePort, false)
}

// StartTransparentLearning enables session-local public dial recording only.
func StartTransparentLearning(synthetic *Synthetic, policy *Policy, session, name string, agent netip.Addr, serviceHost string, servicePort uint16, learning bool) (*Transparent, error) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero})
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	cancel := func() {}
	if learning {
		ctx, cancel = context.WithCancel(ctx)
	}
	gate := &Transparent{Address: listener.Addr().String(), listener: listener, synthetic: synthetic, policy: policy, session: session, name: name, agent: agent, connections: map[net.Conn]bool{}, slots: make(chan struct{}, 16), servicePort: servicePort, serviceHost: serviceHost, learning: learning, ctx: ctx, cancel: cancel, closeDone: make(chan struct{})}
	go gate.accept()
	return gate, nil
}

func (g *Transparent) Close() {
	g.closeOnce.Do(func() {
		g.mu.Lock()
		g.closed = true
		g.cancel()
		_ = g.listener.Close()
		for conn := range g.connections {
			_ = conn.Close()
		}
		g.mu.Unlock()
		if g.learning {
			g.wg.Wait()
		}
		g.policy.End(g.session)
		close(g.closeDone)
	})
	<-g.closeDone
}

// CloseAndLearningDials stops new connections and waits for all in-flight
// public dial callbacks before returning a detached bounded observation list.
func (g *Transparent) CloseAndLearningDials() ([]Target, bool) {
	g.Close()
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]Target(nil), g.dials...), g.dropped
}

func (g *Transparent) accept() {
	for {
		conn, err := g.listener.AcceptTCP()
		if err != nil {
			return
		}
		g.mu.Lock()
		if g.closed {
			g.mu.Unlock()
			_ = conn.Close()
			continue
		}
		select {
		case g.slots <- struct{}{}:
			if g.learning {
				g.connections[conn] = true
			}
			g.wg.Add(1)
			g.mu.Unlock()
			go func() {
				defer func() {
					g.mu.Lock()
					delete(g.connections, conn)
					g.mu.Unlock()
					_ = conn.Close()
					<-g.slots
					g.wg.Done()
				}()
				g.forward(conn)
			}()
		default:
			g.mu.Unlock()
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
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(g.ctx, 10*time.Second)
	defer cancel()
	var epoch *policyEpoch
	if !g.learning {
		var leaseCancel context.CancelFunc
		var allowed bool
		ctx, leaseCancel, epoch, allowed = g.policy.beginDial(ctx, g.session, g.name, target)
		if !allowed {
			return
		}
		defer leaseCancel()
	}
	var upstream net.Conn
	if target.Host == g.serviceHost && target.Port == g.servicePort && g.servicePort != 0 {
		upstream, err = (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(g.servicePort))))
	} else {
		upstream, err = dialVettedPublic(ctx, target)
	}
	if err != nil {
		return
	}
	defer func() { _ = upstream.Close() }()
	if ctx.Err() != nil || !g.learning && !g.policy.admitDial(g.session, target, epoch) {
		return
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	if g.learning && (target.Host != g.serviceHost || target.Port != g.servicePort || g.servicePort == 0) {
		if len(g.dials) >= 4096 {
			g.dropped = true
			g.mu.Unlock()
			return
		}
		g.dials = append(g.dials, target)
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
