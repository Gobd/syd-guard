package guest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Gobd/syd-guard/internal/policy"
	"github.com/Gobd/syd-guard/internal/system"
)

// The namespace has only loopback and a TUN. Nothing can reach the host except
// through these handlers, including in learn mode. No SOCKS server or global
// routing changes are needed: tun2socks' gVisor adapters call our policy dialer.
const (
	networkGateway = "192.0.2.2"
	maxConnections = 256
	maxFlows       = 1024
)

// Connection is a bounded, metadata-only session history; no payloads/URLs.
type Connection struct {
	ID          string     `json:"id"`
	Protocol    string     `json:"protocol"`
	Scheme      string     `json:"scheme,omitempty"`
	Port        string     `json:"port"`
	Destination string     `json:"destination"`
	Hostname    string     `json:"hostname,omitempty"`
	HTTPHost    string     `json:"httpHost,omitempty"`
	SNI         string     `json:"sni,omitempty"`
	State       string     `json:"state"`
	Error       string     `json:"error,omitempty"`
	Started     time.Time  `json:"started"`
	Ended       *time.Time `json:"ended,omitempty"`
	Sent        int64      `json:"sent"`
	Received    int64      `json:"received"`
}

type network struct {
	d           *Daemon
	s           *Session
	mu          sync.Mutex
	connections []*Connection
	active      map[string]func()
	flows       chan struct{}
	ctx         context.Context
	cancel      context.CancelFunc
	stop        func()
}

func newNetwork(d *Daemon, s *Session) *network {
	ctx, cancel := context.WithCancel(context.Background())
	return &network{d: d, s: s, active: map[string]func(){}, flows: make(chan struct{}, maxFlows), ctx: ctx, cancel: cancel}
}

func (n *network) begin(proto, dest, host string, closeFlow func()) *Connection {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.ctx.Err() != nil {
		return nil
	}
	_, port, _ := net.SplitHostPort(dest)
	c := &Connection{ID: system.NewID(), Protocol: proto, Port: port, Destination: dest, Hostname: host, State: "connecting", Started: time.Now()}
	if len(n.connections) >= maxConnections {
		n.connections = n.connections[1:]
	}
	n.connections = append(n.connections, c)
	n.active[c.ID] = closeFlow
	n.d.events.Notify()
	return c
}

func (n *network) snapshot() []Connection {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]Connection, 0, len(n.connections))
	for i := len(n.connections) - 1; i >= 0; i-- {
		x := n.connections[i]
		c := Connection{ID: x.ID, Protocol: x.Protocol, Scheme: x.Scheme, Port: x.Port, Destination: x.Destination, Hostname: x.Hostname, HTTPHost: x.HTTPHost, SNI: x.SNI, State: x.State, Error: x.Error, Started: x.Started, Ended: x.Ended}
		c.Sent = atomic.LoadInt64(&x.Sent)
		c.Received = atomic.LoadInt64(&x.Received)
		out = append(out, c)
	}
	return out
}

func (n *network) finish(c *Connection, err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.active, c.ID)
	now := time.Now()
	c.Ended, c.State = &now, "closed"
	if err != nil {
		c.State, c.Error = "denied/error", truncate(err.Error(), 200)
	}
	n.d.events.Notify()
}

func (n *network) close() {
	n.cancel()
	n.mu.Lock()
	for _, closeFlow := range n.active {
		closeFlow()
	}
	stop := n.stop
	n.mu.Unlock()
	if stop != nil {
		stop()
	}
}

// Revocation closes existing flows too; a conservative reset avoids keeping
// traffic alive on a removed rule, including overlapping/global grants.
func (n *network) revoke() {
	n.mu.Lock()
	for _, closeFlow := range n.active {
		closeFlow()
	}
	n.mu.Unlock()
}

func (n *network) hostFor(dest string) string {
	host, _, _ := net.SplitHostPort(dest)
	if name := n.s.dns.nameOf(host); name != "" {
		return name
	}
	return host
}

// dialTarget never treats DNS's synthetic address as an upstream address.
// Unknown synthetic addresses and arbitrary DNS servers fail closed.
func (n *network) dialTarget(ctx context.Context, proto, scheme, host, port string) (string, error) {
	p, _ := strconv.Atoi(port)
	if host == networkGateway && ((proto == "tcp" && p == n.s.ProxyPort) || slices.Contains(n.s.LocalPorts, p)) {
		return net.JoinHostPort("127.0.0.1", port), nil
	}
	ip, literal := netip.ParseAddr(host)
	if literal == nil && (synthetic4.Contains(ip.Unmap()) || synthetic6.Contains(ip)) {
		return "", errors.New("unknown session DNS address")
	}
	if port == "53" {
		return "", errors.New("use the session DNS resolver")
	}
	if literal == nil {
		rules := []policy.Rules{n.d.store.Get(system.GlobalRulesPath()), n.d.store.Get(n.s.RulesFile)}
		target := host + "!" + port
		if policy.Ignored(rules, "connect", target) {
			return "", errors.New("destination is always denied")
		}
		if addrClass(ip) == "blocked" {
			return "", errors.New("local/metadata destination blocked")
		}
		for _, r := range rules {
			for _, p := range r.Connect {
				if matchConnect(p, proto, ip, port) {
					return net.JoinHostPort(host, port), nil
				}
			}
		}
		// Name approvals do not authorize literal IPs. An IP needs its own
		// host rule or explicit connect rule, never somebody else's DNS answer.
	}
	addr, _, err := n.d.decide(ctx, n.s, scheme, host, port)
	return addr, err
}

func matchConnect(pattern, proto string, ip netip.Addr, port string) bool {
	if p, rest, ok := strings.Cut(pattern, "!"); ok && (p == "tcp" || p == "udp") {
		if p != proto {
			return false
		}
		pattern = rest
	}
	host, ports, ok := strings.Cut(pattern, "!")
	if !ok {
		return false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Unmap() != ip.Unmap() {
			return false
		}
	} else if prefix, err := netip.ParsePrefix(host); err != nil || !prefix.Contains(ip.Unmap()) {
		return false
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	lo, hi, rangeOK := strings.Cut(ports, "-")
	if !rangeOK {
		hi = lo
	}
	a, e1 := strconv.Atoi(lo)
	b, e2 := strconv.Atoi(hi)
	return e1 == nil && e2 == nil && a <= p && p <= b
}

func (n *network) tcp(client net.Conn, dest string) {
	defer func() { _ = client.Close() }()
	host, port := n.hostFor(dest), ""
	_, port, _ = net.SplitHostPort(dest)
	ctx, cancel := context.WithCancel(n.ctx)
	defer cancel()
	var up net.Conn
	var upMu sync.Mutex
	closeFlow := func() {
		cancel()
		_ = client.Close()
		upMu.Lock()
		if up != nil {
			_ = up.Close()
		}
		upMu.Unlock()
	}
	if host == networkGateway && port == "53" {
		n.dnsTCP(client)
		return
	}
	if host == networkGateway && port == strconv.Itoa(n.s.ProxyPort) {
		conn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", port))
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		stop := context.AfterFunc(ctx, func() { _ = conn.Close(); _ = client.Close() })
		defer stop()
		relay(client, conn, client, nil, nil)
		return
	}
	c := n.begin("tcp", dest, host, closeFlow)
	if c == nil {
		return
	}
	var result error
	defer func() { closeFlow(); n.finish(c, result) }()
	in := bufio.NewReaderSize(client, 64<<10)
	scheme := "tcp"
	// Only web ports require inspection before dialing. Other protocols may
	// be server-first (SSH, SMTP, databases), so never wait for their hello.
	if host != networkGateway && (port == "80" || port == "443") {
		_ = client.SetReadDeadline(time.Now().Add(15 * time.Second))
		var httpHost, sni string
		scheme, httpHost, sni, result = sniffWeb(in, host, port)
		_ = client.SetReadDeadline(time.Time{})
		n.mu.Lock()
		c.HTTPHost, c.SNI = httpHost, sni
		n.mu.Unlock()
		if result != nil {
			return
		}
	}
	n.mu.Lock()
	c.Scheme = scheme
	n.mu.Unlock()
	addr, err := n.dialTarget(ctx, "tcp", scheme, host, port)
	if err != nil {
		result = err
		return
	}
	conn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		result = err
		return
	}
	upMu.Lock()
	up = conn
	upMu.Unlock()
	if ctx.Err() != nil {
		return
	}
	n.mu.Lock()
	c.State, c.Destination = "active", addr
	n.mu.Unlock()
	n.d.events.Notify()
	relay(client, conn, in, &c.Sent, &c.Received)
}

func sniffWeb(in *bufio.Reader, host, port string) (scheme, httpHost, sni string, err error) {
	first, err := in.Peek(1)
	if err != nil {
		return "", "", "", err
	}
	if first[0] == 0x16 {
		sni, err = peekServerName(in)
		if err != nil {
			return "", "", "", err
		}
		if sni != "" && !strings.EqualFold(strings.TrimSuffix(sni, "."), host) {
			return "", "", sni, errors.New("TLS name differs from DNS destination")
		}
		if sni == "" {
			return "tcp", "", "", nil
		}
		return "https", "", sni, nil
	}
	if port != "80" {
		return "tcp", "", "", nil
	}
	// Peek only: preserve the bytes. A bounded header prevents a hostile
	// client from allocating an unlimited request before policy approval.
	for size := 1; size <= in.Size(); size++ {
		b, e := in.Peek(size)
		if e != nil {
			return "", "", "", e
		}
		if size >= 4 && string(b[size-4:]) == "\r\n\r\n" {
			r, e := http.ReadRequest(bufio.NewReader(strings.NewReader(string(b))))
			if e != nil {
				return "tcp", "", "", nil
			}
			httpHost = r.Host
			name := httpHost
			if h, _, e := net.SplitHostPort(name); e == nil {
				name = h
			}
			if !strings.EqualFold(strings.TrimSuffix(name, "."), host) {
				return "", httpHost, "", errors.New("HTTP Host differs from DNS destination")
			}
			// Transparent HTTP needs a raw grant: unlike the HTTP proxy it
			// cannot check every later request on a persistent connection.
			return "tcp", httpHost, "", nil
		}
	}
	return "", "", "", errors.New("HTTP header too large")
}

func relay(client, up net.Conn, in io.Reader, sent, received *int64) {
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(countWriter{up, sent}, in)
		if c, ok := up.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		} else {
			_ = up.Close()
		}
		close(done)
	}()
	_, _ = io.Copy(countWriter{client, received}, up)
	_ = client.Close()
	_ = up.Close()
	<-done
}

type countWriter struct {
	io.Writer
	count *int64
}

func (w countWriter) Write(b []byte) (int, error) {
	n, err := w.Writer.Write(b)
	if w.count != nil {
		atomic.AddInt64(w.count, int64(n))
	}
	return n, err
}

func networkRulesRemoved(before, after policy.Rules) bool {
	for _, p := range before.Hosts {
		if !slices.Contains(after.Hosts, p) {
			return true
		}
	}
	for _, p := range before.Connect {
		if !slices.Contains(after.Connect, p) {
			return true
		}
	}
	for _, p := range after.Ignore {
		if !slices.Contains(before.Ignore, p) {
			return true
		}
	}
	return false
}

func (n *network) dnsTCP(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	for {
		q, err := readTCPMsg(c)
		if err != nil {
			return
		}
		if writeTCPMsg(c, n.s.dns.handle(q, "tcp")) != nil {
			return
		}
	}
}

func (n *network) udp(client net.Conn, dest string) {
	defer func() { _ = client.Close() }()
	host := n.hostFor(dest)
	_, port, _ := net.SplitHostPort(dest)
	ctx, cancel := context.WithCancel(n.ctx)
	defer cancel()
	var up net.Conn
	var upMu sync.Mutex
	closeFlow := func() {
		cancel()
		_ = client.Close()
		upMu.Lock()
		if up != nil {
			_ = up.Close()
		}
		upMu.Unlock()
	}
	c := n.begin("udp", dest, host, closeFlow)
	if c == nil {
		return
	}
	var result error
	defer func() { closeFlow(); n.finish(c, result) }()
	buf := make([]byte, 65535)
	if host == networkGateway && port == "53" {
		for {
			_ = client.SetReadDeadline(time.Now().Add(30 * time.Second))
			size, err := client.Read(buf)
			if err != nil {
				return
			}
			resp := n.s.dns.handle(buf[:size], "udp")
			if _, err := client.Write(resp); err != nil {
				return
			}
		}
	}
	addr, err := n.dialTarget(ctx, "udp", "udp", host, port)
	if err != nil {
		result = err
		return
	}
	conn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "udp", addr)
	if err != nil {
		result = err
		return
	}
	upMu.Lock()
	up = conn
	upMu.Unlock()
	if ctx.Err() != nil {
		return
	}
	n.mu.Lock()
	c.State, c.Destination = "active", addr
	n.mu.Unlock()
	done := make(chan struct{})
	copyPackets := func(dst, src net.Conn, counter *int64) {
		packet := make([]byte, 65535)
		for {
			_ = src.SetReadDeadline(time.Now().Add(2 * time.Minute))
			size, err := src.Read(packet)
			if err != nil {
				return
			}
			if _, err := dst.Write(packet[:size]); err != nil {
				return
			}
			atomic.AddInt64(counter, int64(size))
		}
	}
	go func() { copyPackets(conn, client, &c.Sent); closeFlow(); close(done) }()
	copyPackets(client, conn, &c.Received)
	closeFlow()
	<-done
}

func networkBroker(port int) string { return fmt.Sprintf("http://%s:%d", networkGateway, port) }
