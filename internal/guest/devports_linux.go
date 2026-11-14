//go:build linux

package guest

import (
	"bufio"
	"encoding/hex"
	"io"
	"log"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Owner side of the dev-server relay (runs inside the agent's namespace).

// listeningPorts parses /proc/net/tcp{,6} of the calling process's network
// namespace: TCP sockets in LISTEN state on ports >= minDevPort.
func listeningPorts() []int {
	var out []int
	for _, f := range []string{"/proc/self/net/tcp", "/proc/self/net/tcp6"} {
		file, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(file)
		sc.Scan() // header
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 4 || fields[3] != "0A" { // 0A = LISTEN
				continue
			}
			_, portHex, ok := strings.Cut(fields[1], ":")
			if !ok {
				continue
			}
			b, err := hex.DecodeString(portHex)
			if err != nil || len(b) != 2 {
				continue
			}
			if p := int(b[0])<<8 | int(b[1]); p >= minDevPort && !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
		_ = file.Close()
	}
	slices.Sort(out)
	return out
}

// watchDevPorts runs in the namespace owner: report listening ports (except
// the owner's own --local-port relays) and serve relayed connections.
func watchDevPorts(id string, own []int, done <-chan struct{}) {
	_ = os.Remove(portsSocket(id))
	ln, err := net.Listen("unix", portsSocket(id))
	if err != nil {
		log.Printf("dev ports: %v", err)
		return
	}
	_ = os.Chmod(portsSocket(id), 0o600)
	go func() { <-done; _ = ln.Close(); _ = os.Remove(portsSocket(id)) }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go relayIn(c)
		}
	}()
	var last []int
	lastSent := time.Time{}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-done:
			return
		case <-tick.C:
		}
		ports := slices.DeleteFunc(listeningPorts(), func(p int) bool { return slices.Contains(own, p) })
		// Resend periodically too: a restarted daemon catches up on its own.
		if slices.Equal(ports, last) && time.Since(lastSent) < 5*time.Second {
			continue
		}
		if Call("POST", "/internal/ports", map[string]any{"Session": id, "Ports": ports}, nil) == nil {
			last, lastSent = ports, time.Now()
		}
	}
}

// relayIn connects one relayed connection to the agent's server. The daemon
// sends the port as the first line.
func relayIn(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	// Read the header byte by byte: a buffered reader could swallow the start
	// of the relayed stream that follows it.
	var line []byte
	one := make([]byte, 1)
	for len(line) < 8 {
		if _, err := io.ReadFull(c, one); err != nil {
			return
		}
		if one[0] == '\n' {
			break
		}
		line = append(line, one[0])
	}
	port, err := strconv.Atoi(string(line))
	if err != nil || port < minDevPort || port > 65535 {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	var up net.Conn
	for _, host := range []string{"127.0.0.1", "::1"} {
		if up, err = net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 2*time.Second); err == nil {
			break
		}
	}
	if up == nil {
		return
	}
	relay(c, up, c, nil, nil)
}
