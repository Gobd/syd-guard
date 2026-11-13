//go:build linux

package guest

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Gobd/syd-guard/internal/system"
)

// Per-flow handling for the session's TUN (Linux-only, like the TUN itself).

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

func (n *network) hostFor(dest string) string {
	host, _, _ := net.SplitHostPort(dest)
	if name := n.s.dns.nameOf(host); name != "" {
		return name
	}
	return host
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
