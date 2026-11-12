package network

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// Gateway exposes only a forward-proxy data plane for one opaque session.
// It has no approval routes or operator credentials.
type Gateway struct {
	Address       string
	policy        *Policy
	session, name string
	server        *http.Server
	mu            sync.Mutex
	tunnels       map[net.Conn]bool
	slots         chan struct{}
}

func Start(policy *Policy, session, name string) (*Gateway, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	gate := &Gateway{Address: listener.Addr().String(), policy: policy, session: session, name: name, tunnels: map[net.Conn]bool{}, slots: make(chan struct{}, 16)}
	gate.server = &http.Server{Handler: http.HandlerFunc(gate.handle), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	go func() { _ = gate.server.Serve(listener) }()
	return gate, nil
}

func (g *Gateway) Close() {
	_ = g.server.Close()
	g.mu.Lock()
	defer g.mu.Unlock()
	for conn := range g.tunnels {
		_ = conn.Close()
	}
	g.policy.End(g.session)
}

func (g *Gateway) handle(w http.ResponseWriter, r *http.Request) {
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		http.Error(w, "session proxy capacity reached", http.StatusTooManyRequests)
		return
	}
	authority := r.URL.Host
	if r.Method == http.MethodConnect {
		authority = r.Host
	}
	host, portText, err := net.SplitHostPort(authority)
	if err != nil && r.Method != http.MethodConnect && r.URL.Scheme == "http" {
		host = authority
		portText = "80"
		err = nil
	}
	port, parseErr := strconv.ParseUint(portText, 10, 16)
	target, targetErr := Canonical(host, uint16(port))
	if err != nil || parseErr != nil || targetErr != nil || r.Method != http.MethodConnect && (r.URL.Scheme != "http" || r.URL.User != nil) {
		http.Error(w, "requires an exact HTTP/CONNECT DNS target", http.StatusBadRequest)
		return
	}
	if !g.policy.Check(g.session, g.name, target) {
		http.Error(w, "network target pending operator approval; approve then retry", http.StatusForbidden)
		return
	}
	upstream, err := dialPublic(r.Context(), target)
	if err != nil {
		http.Error(w, "target cannot be reached through vetted public DNS", http.StatusBadGateway)
		return
	}
	defer func() { _ = upstream.Close() }()
	if r.Method == http.MethodConnect {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "CONNECT unavailable", 500)
			return
		}
		downstream, buffer, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = downstream.Close() }()
		g.mu.Lock()
		g.tunnels[downstream] = true
		g.tunnels[upstream] = true
		g.mu.Unlock()
		defer func() { g.mu.Lock(); delete(g.tunnels, downstream); delete(g.tunnels, upstream); g.mu.Unlock() }()
		_ = downstream.SetDeadline(time.Now().Add(5 * time.Minute))
		_ = upstream.SetDeadline(time.Now().Add(5 * time.Minute))
		if _, err := buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if err := buffer.Flush(); err != nil {
			return
		}
		done := make(chan struct{})
		go func() { _, _ = io.Copy(upstream, buffer); _ = upstream.Close(); close(done) }()
		_, _ = io.Copy(downstream, upstream)
		_ = downstream.Close()
		<-done
		return
	}
	// Strip hop-by-hop and proxy credentials before sending an origin request.
	r.Header.Del("Proxy-Authorization")
	r.Header.Del("Proxy-Connection")
	for _, header := range []string{"Connection", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		r.Header.Del(header)
	}
	r.Host = net.JoinHostPort(target.Host, strconv.Itoa(int(target.Port)))
	r.RequestURI = ""
	r.Close = true
	r.Body = http.MaxBytesReader(w, r.Body, 32*1024*1024)
	_ = upstream.SetDeadline(time.Now().Add(30 * time.Second))
	if err := r.Write(upstream); err != nil {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	// A dedicated one-shot HTTP transport owns this already-vetted connection.
	// ReadResponse requires buffered parsing but never resolves/dials another host.
	response, err := http.ReadResponse(bufio.NewReader(upstream), r)
	if err != nil {
		http.Error(w, "upstream response failed", http.StatusBadGateway)
		return
	}
	defer func() { _ = response.Body.Close() }()
	for key, values := range response.Header {
		if key == "Connection" || key == "Transfer-Encoding" {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

func dialPublic(ctx context.Context, target Target) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", target.Host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("no addresses")
	}
	// Fail closed on a mixed public/private answer instead of selecting the public
	// half and allowing a later retry to hit metadata or a local control plane.
	for _, address := range addresses {
		if !publicAddress(address) {
			return nil, fmt.Errorf("non-public DNS answer")
		}
	}
	var last error
	for _, address := range addresses {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(address.String(), strconv.Itoa(int(target.Port))))
		if err == nil {
			return conn, nil
		}
		last = err
	}
	return nil, last
}

func publicAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range blockedRanges {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var blockedRanges = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001:db8::/32")}
