package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Gobd/syd-guard/internal/netns"
	"github.com/Gobd/syd-guard/internal/network"
	"github.com/Gobd/syd-guard/internal/session"
	"github.com/Gobd/syd-guard/internal/syd"
)

// Service is a trusted launcher declaration, never derived from workload environment.
type Service struct {
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
}

// Registration is the authenticated launcher/controller contract.
type Registration struct {
	Project      string    `json:"project"`
	Name         string    `json:"name"`
	Command      []string  `json:"command"`
	PID          int       `json:"pid"`
	NetworkProxy bool      `json:"network_proxy"`
	Transparent  bool      `json:"transparent"`
	Services     []Service `json:"services,omitempty"`
}

// NetworkEvent is either a trusted separate-FD Syd record or a parsed synthetic endpoint.
type NetworkEvent struct {
	Record   json.RawMessage `json:"record,omitempty"`
	Endpoint string          `json:"endpoint,omitempty"`
}
type transparentSession struct {
	synthetic   *network.Synthetic
	dns         *network.DNS
	gate        *network.Transparent
	runtime     *netns.Runtime
	socket      string
	socketInfo  os.FileInfo
	servicePort uint16
	serviceHost string
	ending      bool
}

func servicePort(services []Service) (uint16, error) {
	if len(services) > 1 {
		return 0, fmt.Errorf("at most one trusted service is supported")
	}
	if len(services) == 0 {
		return 0, nil
	}
	name := services[0].Name
	if name == "" || len(name) > 63 || strings.Contains(name, ".") || strings.ToLower(name) != name {
		return 0, fmt.Errorf("trusted service name must be a lowercase DNS label")
	}
	if _, err := network.Canonical(name+".sydguard.internal", 1); err != nil {
		return 0, fmt.Errorf("trusted service name must be a lowercase DNS label")
	}
	host, text, err := net.SplitHostPort(services[0].Endpoint)
	if err != nil || host != "127.0.0.1" {
		return 0, fmt.Errorf("trusted service must be exact IPv4 loopback")
	}
	n, err := strconv.ParseUint(text, 10, 16)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != text {
		return 0, fmt.Errorf("trusted service requires canonical port")
	}
	return uint16(n), nil
}

func listenerPort(address string) (uint16, error) {
	_, text, err := net.SplitHostPort(address)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(text, 10, 16)
	return uint16(n), err
}

// Caller holds gatesMu; this serializes publication with teardown and decisions.
func (server *Server) startTransparent(ctx context.Context, value session.Session, host string, port uint16) (*transparentSession, netns.Topology, error) {
	topology, err := netns.New()
	if err != nil {
		return nil, topology, err
	}
	t := &transparentSession{synthetic: network.NewSyntheticWithAllocator(server.allocator), servicePort: port, serviceHost: host}
	t.dns, err = network.StartDNS(t.synthetic, topology.Agent)
	if err != nil {
		return nil, topology, err
	}
	t.gate, err = network.StartTransparentWithService(t.synthetic, server.network, value.ID, value.Name, topology.Agent, host, port)
	if err != nil {
		t.dns.Close()
		return nil, topology, err
	}
	dp, err := listenerPort(t.dns.Address)
	if err == nil {
		var tp uint16
		tp, err = listenerPort(t.gate.Address)
		if err == nil {
			var state string
			state, err = server.stateDirectory()
			if err == nil {
				err = privateState(state)
			}
			if err == nil {
				t.runtime, err = netns.Create(ctx, topology, dp, tp, state)
			}
		}
	}
	if err != nil {
		t.gate.Close()
		t.dns.Close()
		return nil, topology, err
	}
	if err = ctx.Err(); err != nil {
		t.gate.Close()
		t.dns.Close()
		if closeErr := t.runtime.Close(); closeErr != nil {
			return nil, topology, fmt.Errorf("%w; rollback: %v", err, closeErr)
		}
		return nil, topology, err
	}
	return t, topology, nil
}

func (server *Server) stateDirectory() (string, error) {
	if server.state != "" {
		return server.state, nil
	}
	return StateDirectory()
}

// Validate every parent and preserve the socket identity for subsequent grants.
func (server *Server) validateNetworkSocket(path string) (os.FileInfo, error) {
	state, err := server.stateDirectory()
	if err != nil {
		return nil, err
	}
	if err = privateState(state); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("invalid IPC path")
	}
	rel, err := filepath.Rel(filepath.Join(state, "runs"), path)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "run-") || parts[0] == "run-" || parts[1] != "syd.sock" {
		return nil, fmt.Errorf("IPC must be under a protected run authority")
	}
	for _, dir := range []string{filepath.Join(state, "runs"), filepath.Join(state, "runs", parts[0])} {
		info, e := os.Lstat(dir)
		if e != nil {
			return nil, e
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
			return nil, fmt.Errorf("unsafe IPC authority directory")
		}
		if e = owned(info); e != nil {
			return nil, e
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("unsafe Syd socket")
	}
	if err = owned(info); err != nil {
		return nil, err
	}
	return info, nil
}

func (server *Server) networkReady(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Socket string `json:"socket"`
	}
	if err := decode(w, r, &input); err != nil {
		reply(w, 400, map[string]string{"error": err.Error()})
		return
	}
	server.gatesMu.Lock()
	defer server.gatesMu.Unlock()
	t := server.transparent[r.PathValue("id")]
	value, ok := server.registry.Get(r.PathValue("id"))
	if t == nil || t.ending || server.closed || !ok || value.State != session.Running {
		reply(w, 409, map[string]string{"error": "no active transparent session"})
		return
	}
	if t.socket != "" {
		reply(w, 409, map[string]string{"error": "network IPC already registered"})
		return
	}
	info, err := server.validateNetworkSocket(input.Socket)
	if err != nil {
		reply(w, 400, map[string]string{"error": "unsafe network IPC authority"})
		return
	}
	for _, other := range server.transparent {
		if other.socket == input.Socket || other.socketInfo != nil && os.SameFile(other.socketInfo, info) {
			reply(w, 409, map[string]string{"error": "network IPC already bound"})
			return
		}
	}
	if _, err = (syd.IPC{Socket: input.Socket}).Version(r.Context()); err != nil {
		reply(w, 409, map[string]string{"error": "Syd IPC capability check failed"})
		return
	}
	current, err := server.validateNetworkSocket(input.Socket)
	if err != nil || !os.SameFile(info, current) {
		reply(w, 409, map[string]string{"error": "Syd socket changed"})
		return
	}
	t.socket, t.socketInfo = input.Socket, info
	reply(w, 200, map[string]string{"status": "registered"})
}

func (server *Server) networkEvent(w http.ResponseWriter, r *http.Request) {
	var input NetworkEvent
	if err := decode(w, r, &input); err != nil {
		reply(w, 400, map[string]string{"error": err.Error()})
		return
	}
	var endpoint netip.AddrPort
	var ok bool
	if len(input.Record) > 0 && input.Endpoint == "" {
		endpoint, ok = syd.ParseSyntheticConnectDenial(input.Record)
	} else if len(input.Record) == 0 && input.Endpoint != "" {
		var err error
		endpoint, err = netip.ParseAddrPort(input.Endpoint)
		ok = err == nil && endpoint.String() == input.Endpoint && endpoint.Addr().Is4() && netip.MustParsePrefix("198.18.0.0/15").Contains(endpoint.Addr()) && endpoint.Port() != 0
	}
	if !ok {
		reply(w, 400, map[string]string{"error": "invalid synthetic TCP denial"})
		return
	}
	server.gatesMu.Lock()
	defer server.gatesMu.Unlock()
	id := r.PathValue("id")
	t := server.transparent[id]
	value, active := server.registry.Get(id)
	if t == nil || t.ending || server.closed || !active || value.State != session.Running || t.socket == "" {
		reply(w, 409, map[string]string{"error": "network session not ready"})
		return
	}
	host, ok := t.synthetic.Host(endpoint.Addr())
	if !ok {
		reply(w, 400, map[string]string{"error": "synthetic address is not mapped to this session"})
		return
	}
	target, err := network.Canonical(host, endpoint.Port())
	if err != nil {
		reply(w, 400, map[string]string{"error": "invalid target"})
		return
	}
	if network.ReservedServiceHost(target.Host) {
		if t.servicePort == 0 || target.Host != t.serviceHost || target.Port != t.servicePort {
			reply(w, 400, map[string]string{"error": "service not declared for this exact port"})
			return
		}
		err = server.network.AllowTrusted(id, target, func() error { return server.grantSynthetic(r.Context(), t, endpoint) })
		if err != nil {
			reply(w, 409, map[string]string{"error": "trusted service grant failed"})
			return
		}
		reply(w, 200, map[string]string{"status": "trusted service applied; retry"})
		return
	}
	server.network.Check(id, value.Name, target)
	reply(w, 200, map[string]string{"status": "observed"})
}

func (server *Server) decideNetwork(ctx context.Context, d network.Decision) error {
	if err := lockContext(ctx, &server.gatesMu); err != nil {
		return err
	}
	defer server.gatesMu.Unlock()
	if d.Scope == "saved" {
		return fmt.Errorf("saved network rules unavailable")
	}
	return server.network.DecideWithApplyContext(ctx, d, func(p network.Pending) error {
		t := server.transparent[p.SessionID]
		if t == nil {
			if _, ok := server.gates[p.SessionID]; !ok {
				return fmt.Errorf("session ended")
			}
			return nil
		}
		value, ok := server.registry.Get(p.SessionID)
		if !ok || t.ending || server.closed || value.State != session.Running || t.socket == "" {
			return fmt.Errorf("network session not ready")
		}
		address, exists := t.synthetic.ExistingAddress(p.Target.Host)
		if !exists {
			return fmt.Errorf("synthetic mapping unavailable")
		}
		host, ok := t.synthetic.Host(address)
		if !ok || host != p.Target.Host {
			return fmt.Errorf("synthetic mapping changed")
		}
		return server.grantSynthetic(ctx, t, netip.AddrPortFrom(address, p.Target.Port))
	})
}

func (server *Server) grantSynthetic(ctx context.Context, t *transparentSession, endpoint netip.AddrPort) error {
	info, err := server.validateNetworkSocket(t.socket)
	if err != nil || !os.SameFile(t.socketInfo, info) {
		return fmt.Errorf("syd socket changed or unavailable")
	}
	return (syd.IPC{Socket: t.socket}).GrantSyntheticTCP(ctx, endpoint)
}
