package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

const approvalTimeout = 10 * time.Minute

// startProxy gives a session its own HTTP(S) proxy. Syd only lets the agent
// connect to this port, so every web request is decided here by host name.
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

var upstream = &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 15 * time.Second}).DialContext, ForceAttemptHTTP2: false, IdleConnTimeout: 90 * time.Second}

func (d *Daemon) serveProxy(s *Session, w http.ResponseWriter, r *http.Request) {
	hostport := r.Host
	if r.Method != http.MethodConnect {
		if r.URL.Host == "" {
			http.Error(w, "sydguard proxy: absolute URL required", http.StatusBadRequest)
			return
		}
		hostport = r.URL.Host
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host, port = hostport, "80"
		if r.URL.Scheme == "https" {
			port = "443"
		}
	}
	if !d.hostAllowed(s, host, port) {
		http.Error(w, fmt.Sprintf("sydguard: %s:%s was not approved", host, port), http.StatusForbidden)
		return
	}
	target := net.JoinHostPort(host, port)
	if r.Method == http.MethodConnect {
		up, err := net.DialTimeout("tcp", target, 15*time.Second)
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
			b, _ := buf.Reader.Peek(n)
			_, _ = up.Write(b)
		}
		go func() { _, _ = io.Copy(up, client); _ = up.Close() }()
		_, _ = io.Copy(client, up)
		_ = client.Close()
		return
	}
	r.RequestURI = ""
	for _, h := range hopHeaders {
		r.Header.Del(h)
	}
	resp, err := upstream.RoundTrip(r)
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

// hostAllowed checks saved rules; if nothing matches it shows a card and holds
// the request open until the user decides (learn mode allows and records).
func (d *Daemon) hostAllowed(s *Session, host, port string) bool {
	host = strings.ToLower(strings.Trim(host, "[]"))
	if ignored(d.rulesFor(s.Project), "hosts", net.JoinHostPort(host, port)) {
		return false
	}
	for _, project := range []string{"", s.Project} {
		r, err := loadRules(project)
		if err != nil {
			log.Printf("rules: %v", err)
			return false
		}
		for _, p := range r.Hosts {
			if matchHost(p, host, port) {
				return true
			}
		}
	}
	d.mu.Lock()
	if _, live := d.sessions[s.ID]; !live {
		d.mu.Unlock()
		return false
	}
	c := d.addCardLocked(s, "hosts", net.JoinHostPort(host, port), "", s.Learn, false)
	if s.Learn || c == nil {
		d.mu.Unlock()
		return s.Learn
	}
	ch := make(chan bool, 1)
	c.waiters = append(c.waiters, ch)
	d.mu.Unlock()
	select {
	case ok := <-ch:
		return ok
	case <-time.After(approvalTimeout):
		d.mu.Lock()
		for i, w := range c.waiters {
			if w == ch {
				c.waiters = append(c.waiters[:i], c.waiters[i+1:]...)
				break
			}
		}
		d.mu.Unlock()
		return false
	}
}
