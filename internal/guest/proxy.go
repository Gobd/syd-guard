package guest

import (
	"context"
	"fmt"
	"io"
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
	addr, err := d.decide(r.Context(), s, scheme, host, port)
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
		if n := buf.Reader.Buffered(); n > 0 {
			b, _ := buf.Peek(n)
			_, _ = up.Write(b)
		}
		go func() { _, _ = io.Copy(up, client); _ = up.Close() }()
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

// decide returns the vetted ip:port to dial, asking the user when no rule
// matches (the request waits). Learn mode allows and records.
func (d *Daemon) decide(ctx context.Context, s *Session, scheme, host, port string) (string, error) {
	if _, err := policy.ParseHostRule(host); err != nil {
		return "", fmt.Errorf("bad host %q", host)
	}
	target := scheme + "://" + net.JoinHostPort(host, port)
	rules := []policy.Rules{d.store.Get(system.GlobalRulesPath()), d.store.Get(s.RulesFile)}
	if policy.Ignored(rules, "hosts", target) {
		return "", fmt.Errorf("%s is always denied", target)
	}
	addrs, err := resolve(ctx, host)
	if err != nil || len(addrs) == 0 {
		return "", fmt.Errorf("cannot resolve %s", host)
	}
	class := "public"
	for _, a := range addrs {
		switch addrClass(a) {
		case "blocked":
			return "", fmt.Errorf("%s resolves to %s (local addresses are never proxied)", host, a)
		case "private":
			class = "private"
		}
	}
	allowed := func() bool {
		for _, r := range []policy.Rules{d.store.Get(system.GlobalRulesPath()), d.store.Get(s.RulesFile)} {
			for _, p := range r.Hosts {
				if h, err := policy.ParseHostRule(p); err == nil && h.Match(scheme, host, port) && (class == "public" || h.Exact()) {
					return true
				}
			}
		}
		return false
	}
	addr := net.JoinHostPort(addrs[0].Unmap().String(), port)
	if allowed() {
		return addr, nil
	}
	note := ""
	if class == "private" {
		note = fmt.Sprintf("resolves to a private address (%s); only an exact host:port rule allows it", addrs[0])
	}
	d.mu.Lock()
	if _, live := d.sessions[s.ID]; !live {
		d.mu.Unlock()
		return "", fmt.Errorf("session ended")
	}
	c := d.addCardLocked(s, "hosts", target, "", s.Learn && class == "public", false, note)
	if c == nil {
		d.mu.Unlock()
		return "", fmt.Errorf("too many pending approvals")
	}
	if s.Learn && class == "public" {
		d.mu.Unlock()
		return addr, nil
	}
	if d.waitCard(ctx, c, approvalTimeout) && allowed() {
		return addr, nil
	}
	return "", fmt.Errorf("%s was not approved", target)
}
