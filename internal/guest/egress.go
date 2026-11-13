package guest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/Gobd/syd-guard/internal/policy"
	"github.com/Gobd/syd-guard/internal/system"
)

const approvalTimeout = 10 * time.Minute

// startBroker retains the historical port field for session compatibility,
// but serves ONLY the command broker. All egress uses the TUN policy dialer.
func (d *Daemon) startBroker(s *Session) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", s.ProxyPort))
	if err != nil {
		return err
	}
	s.ProxyPort = ln.Addr().(*net.TCPAddr).Port
	s.brokerServer = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect || r.URL.IsAbs() {
			http.Error(w, "forward proxy removed", http.StatusForbidden)
			return
		}
		d.serveBroker(s, w, r)
	}), ReadHeaderTimeout: 30 * time.Second}
	go func() { _ = s.brokerServer.Serve(ln) }()
	return nil
}

// addrClass: "blocked" (loopback, link-local/metadata, multicast, unspecified),
// "private" (LAN/VPN/CGNAT/ULA, incl. the Mac via host.lima.internal), "public".
func addrClass(a netip.Addr) string {
	a = a.Unmap()
	switch {
	case !a.IsValid(), a.IsLoopback(), a.IsUnspecified(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(), a.IsMulticast(), a.IsInterfaceLocalMulticast():
		return "blocked"
	case a.IsPrivate(), netip.MustParsePrefix("100.64.0.0/10").Contains(a), netip.MustParsePrefix("198.18.0.0/15").Contains(a):
		return "private"
	}
	return "public"
}

var resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// decide returns the vetted ip:port to dial. Order matters: the name is
// checked against the rules (or approved by you) BEFORE it is resolved, so an
// agent can't leak data through DNS lookups of names nobody approved. Only
// then is it resolved and the addresses checked (local never, private only
// with an exact rule). Learn mode allows and records.
func (d *Daemon) decide(ctx context.Context, s *Session, scheme, host, port string) (string, []policy.HostRule, error) {
	if _, err := policy.ParseHostRule(host); err != nil {
		return "", nil, fmt.Errorf("bad host %q", host)
	}
	target := scheme + "://" + net.JoinHostPort(host, port)
	matching := func() []policy.HostRule {
		var out []policy.HostRule
		for _, r := range []policy.Rules{d.store.Get(system.GlobalRulesPath()), d.store.Get(s.RulesFile)} {
			for _, p := range r.Hosts {
				if h, err := policy.ParseHostRule(p); err == nil && h.Match(scheme, host, port) {
					out = append(out, h)
				}
			}
		}
		return out
	}
	if policy.Ignored([]policy.Rules{d.store.Get(system.GlobalRulesPath()), d.store.Get(s.RulesFile)}, "hosts", target) {
		return "", nil, fmt.Errorf("%s is always denied", target)
	}
	// A literal IP needs no lookup: refuse local ones right away.
	if ip, err := netip.ParseAddr(host); err == nil && addrClass(ip) == "blocked" {
		return "", nil, fmt.Errorf("%s is a local address (never proxied)", host)
	}
	rules := matching()
	if len(rules) == 0 {
		d.mu.Lock()
		if _, live := d.sessions[s.ID]; !live {
			d.mu.Unlock()
			return "", nil, fmt.Errorf("session ended")
		}
		c := d.addCardLocked(s, "hosts", target, "", s.Learn, false, "")
		switch {
		case c == nil:
			d.mu.Unlock()
			return "", nil, fmt.Errorf("too many pending approvals")
		case s.Learn:
			d.mu.Unlock()
			d.events.Notify()
		case !d.waitCard(ctx, c, approvalTimeout):
			return "", nil, fmt.Errorf("%s was not approved", target)
		default:
			if rules = matching(); len(rules) == 0 {
				return "", nil, fmt.Errorf("%s was not approved", target)
			}
		}
	}
	// Approved by name: now resolve and vet the addresses.
	addrs, err := resolve(ctx, host)
	if err != nil || len(addrs) == 0 {
		return "", nil, fmt.Errorf("cannot resolve %s", host)
	}
	exact := false
	for _, h := range rules {
		exact = exact || h.Exact()
	}
	for _, a := range addrs {
		switch addrClass(a) {
		case "blocked":
			return "", nil, fmt.Errorf("%s resolves to %s (local addresses are never proxied)", host, a)
		case "private":
			if !exact {
				return "", nil, fmt.Errorf("%s resolves to a private address (%s); allow it with an exact rule like %s://%s", host, a, scheme, net.JoinHostPort(host, port))
			}
		}
	}
	return net.JoinHostPort(addrs[0].Unmap().String(), port), rules, nil
}

// peekServerName parses the ClientHello with Go's TLS stack without
// consuming it from in.
func peekServerName(in *bufio.Reader) (string, error) {
	header, err := in.Peek(5)
	if err != nil {
		return "", err
	}
	size := 5 + (int(header[3])<<8 | int(header[4]))
	if size > in.Size() {
		return "", errors.New("ClientHello too large")
	}
	record, err := in.Peek(size)
	if err != nil {
		return "", err
	}
	var name string
	errSeen := errors.New("seen")
	_ = tls.Server(helloConn{bytes.NewReader(record)}, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			name = h.ServerName
			return nil, errSeen
		},
	}).Handshake()
	return name, nil
}

// helloConn feeds recorded bytes to tls.Server and swallows its replies.
type helloConn struct{ r io.Reader }

func (c helloConn) Read(p []byte) (int, error)     { return c.r.Read(p) }
func (helloConn) Write(p []byte) (int, error)      { return len(p), nil }
func (helloConn) Close() error                     { return nil }
func (helloConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (helloConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (helloConn) SetDeadline(time.Time) error      { return nil }
func (helloConn) SetReadDeadline(time.Time) error  { return nil }
func (helloConn) SetWriteDeadline(time.Time) error { return nil }
