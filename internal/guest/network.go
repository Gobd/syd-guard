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
	ports       *devPorts // dev servers mirrored onto the VM's loopback
}

func newNetwork(d *Daemon, s *Session) *network {
	ctx, cancel := context.WithCancel(context.Background())
	return &network{d: d, s: s, active: map[string]func(){}, flows: make(chan struct{}, maxFlows), ctx: ctx, cancel: cancel, ports: newDevPorts(s.ID)}
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

func (n *network) close() {
	n.cancel()
	n.ports.close()
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

func networkBroker(port int) string { return fmt.Sprintf("http://%s:%d", networkGateway, port) }

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
