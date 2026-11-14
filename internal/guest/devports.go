package guest

import (
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"
)

// Dev servers: a server the agent starts listens inside its private network
// namespace, which nothing outside can reach. The namespace owner watches
// which TCP ports are listening there and reports them; the daemon mirrors
// each one on the VM's loopback (which Lima forwards to the host), relaying
// every connection back through the owner's private Unix socket. Inbound
// only: this never gives the agent any new outbound access.

const minDevPort = 1024

func portsSocket(id string) string { return filepath.Join(sessionsDir(), id+".ports.sock") }

// PortView is one dev-server port, for the UI.
type PortView struct {
	Port    int    `json:"port"`
	Exposed bool   `json:"exposed"`
	Error   string `json:"error,omitempty"`
}

// devPorts is the daemon side for one session.
type devPorts struct {
	mu        sync.Mutex
	session   string
	listeners map[int]net.Listener
	errors    map[int]string
}

func newDevPorts(session string) *devPorts {
	return &devPorts{session: session, listeners: map[int]net.Listener{}, errors: map[int]string{}}
}

// set reconciles the exposed ports with what the agent listens on.
func (p *devPorts) set(ports []int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for port, l := range p.listeners {
		if !slices.Contains(ports, port) {
			_ = l.Close()
			delete(p.listeners, port)
		}
	}
	for port := range p.errors {
		if !slices.Contains(ports, port) {
			delete(p.errors, port)
		}
	}
	for _, port := range ports {
		if port < minDevPort || port > 65535 {
			continue
		}
		if _, ok := p.listeners[port]; ok {
			continue
		}
		l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			p.errors[port] = fmt.Sprintf("port %d is already in use on the VM", port)
			continue
		}
		delete(p.errors, port)
		p.listeners[port] = l
		go p.serve(l, port)
	}
}

func (p *devPorts) serve(l net.Listener, port int) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = c.Close() }()
			up, err := net.DialTimeout("unix", portsSocket(p.session), 2*time.Second)
			if err != nil {
				return
			}
			defer func() { _ = up.Close() }()
			if _, err := fmt.Fprintf(up, "%d\n", port); err != nil {
				return
			}
			relay(c, up, c, nil, nil)
		}()
	}
}

func (p *devPorts) view() []PortView {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []PortView
	for port := range p.listeners {
		out = append(out, PortView{Port: port, Exposed: true})
	}
	for port, e := range p.errors {
		out = append(out, PortView{Port: port, Error: e})
	}
	slices.SortFunc(out, func(a, b PortView) int { return a.Port - b.Port })
	return out
}

func (p *devPorts) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for port, l := range p.listeners {
		_ = l.Close()
		delete(p.listeners, port)
	}
}
