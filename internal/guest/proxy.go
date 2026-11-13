package guest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/Gobd/syd-guard/internal/policy"
	"github.com/Gobd/syd-guard/internal/system"
)

const approvalTimeout = 10 * time.Minute

// startProxy gives a session its own HTTP(S) proxy. Syd only lets the agent
// connect to this port, so every web request is decided here by host NAME.
// Adopted sessions reuse their previous port.
func (d *Daemon) startProxy(s *Session) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", s.ProxyPort))
	if err != nil {
		return err
	}
	s.ProxyPort = ln.Addr().(*net.TCPAddr).Port
	s.proxy = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { d.serveProxy(s, w, r) }), ReadHeaderTimeout: 30 * time.Second}
	go func() { _ = s.proxy.Serve(ln) }()
	return nil
}

var hopHeaders = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authorization", "Proxy-Authenticate", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func (d *Daemon) serveProxy(s *Session, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect && r.URL.Host == brokerHost {
		d.serveBroker(s, w, r) // `sydguard cmd` from inside the sandbox
		return
	}
	scheme, hostport := "http", r.Host
	if r.Method == http.MethodConnect {
		scheme = ""
	} else {
		if r.URL.Host == "" || r.URL.Scheme != "http" {
			http.Error(w, "sydguard proxy: absolute http:// URL required (use CONNECT for https)", http.StatusBadRequest)
			return
		}
		hostport = r.URL.Host
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host, port = hostport, "80"
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	if scheme == "" {
		scheme = policy.ConnectScheme(port)
	}
	addr, rules, err := d.decide(r.Context(), s, scheme, host, port)
	if err != nil {
		http.Error(w, "sydguard: "+err.Error(), http.StatusForbidden)
		return
	}
	if r.Method == http.MethodConnect {
		up, err := net.DialTimeout("tcp", addr, 15*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			_ = up.Close()
			return
		}
		client, buf, err := hj.Hijack()
		if err != nil {
			_ = up.Close()
			return
		}
		_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		var pending []byte
		if n := buf.Reader.Buffered(); n > 0 {
			pending, _ = buf.Peek(n)
		}
		in := bufio.NewReaderSize(io.MultiReader(bytes.NewReader(pending), client), 5+16<<10) // a full TLS record
		if !s.Learn {
			_ = client.SetReadDeadline(time.Now().Add(15 * time.Second))
			err := checkTunnel(in, host, rules)
			_ = client.SetReadDeadline(time.Time{})
			if err != nil {
				log.Printf("session %s: refused tunnel to %q: %q", s.ID, host, err.Error()) //nolint:gosec // agent-controlled values are %q-quoted
				_ = client.Close()
				_ = up.Close()
				return
			}
		}
		go func() { _, _ = io.Copy(up, in); _ = up.Close() }()
		_, _ = io.Copy(client, up)
		_ = client.Close()
		return
	}
	// Plain HTTP: dial the vetted address, never re-resolve.
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", addr)
	}}
	r.RequestURI = ""
	for _, h := range hopHeaders {
		r.Header.Del(h)
	}
	resp, err := transport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	for _, h := range hopHeaders {
		resp.Header.Del(h)
	}
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
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

// checkTunnel stops domain fronting: an HTTPS tunnel approved for host must
// actually be TLS to host. It reads the TLS ClientHello (the bytes stay in
// in, to be forwarded) and compares its server name. Non-TLS tunnels, or TLS
// without a name, are only allowed by an explicit tcp:// rule (or to an IP).
func checkTunnel(in *bufio.Reader, host string, rules []policy.HostRule) error {
	raw := false
	for _, h := range rules {
		raw = raw || h.Scheme == "tcp"
	}
	first, err := in.Peek(1)
	if err != nil {
		return err
	}
	if first[0] != 0x16 { // not a TLS handshake record
		if raw {
			return nil
		}
		return errors.New("not TLS (allow raw traffic with a tcp:// rule)")
	}
	name, err := peekServerName(in)
	if err != nil {
		return err
	}
	_, isIP := netip.ParseAddr(host)
	switch {
	case name == "" && (raw || isIP == nil):
		return nil
	case name == "":
		return errors.New("TLS without a server name")
	case !strings.EqualFold(strings.TrimSuffix(name, "."), host):
		return fmt.Errorf("TLS server name %q doesn't match the approved host", name)
	}
	return nil
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
