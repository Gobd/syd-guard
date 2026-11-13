// Package guest is everything that runs on the Linux machine (or Lima VM):
// the daemon that owns sessions, their proxies, DNS servers and live Syd
// updates, and the launcher that runs an agent under Syd.
package guest

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Gobd/syd-guard/internal/api"
	"github.com/Gobd/syd-guard/internal/policy"
	"github.com/Gobd/syd-guard/internal/system"
)

const (
	statusApplied  = "applied"
	statusUpdating = "updating"
	statusUnknown  = "unknown" // a live update failed or timed out; edits stop
)

type Session struct {
	ID          string       `json:"id"`
	Project     string       `json:"project"`
	RulesFile   string       `json:"rulesFile"`
	Cwd         string       `json:"cwd"`
	Cmd         []string     `json:"cmd"`
	Learn       bool         `json:"learn"`
	PID         int          `json:"pid"`
	IPC         string       `json:"ipc"`
	ProxyPort   int          `json:"proxyPort"`
	DNSAddr     string       `json:"dnsAddr,omitempty"`
	Network     bool         `json:"network,omitempty"` // isolated TUN/gVisor namespace
	Connections []Connection `json:"connections,omitempty"`
	LocalPorts  []int        `json:"localPorts,omitempty"`
	Overlays    []string     `json:"overlays,omitempty"` // build dirs kept on the VM disk
	// From the launcher: overlay folder names to look for, env var names to pass.
	OverlayNames []string  `json:"overlayNames,omitempty"`
	EnvNames     []string  `json:"envNames,omitempty"`
	SydPID       int       `json:"sydPid,omitempty"` // Syd's process, for entering its namespaces
	Started      time.Time `json:"started"`
	Launch       []string  `json:"launch"`
	Status       string    `json:"status"`
	LastError    string    `json:"lastError,omitempty"`
	proxy        *http.Server
	dns          *dnsServer
	network      *network
	queue        chan applyOp
}

type applyOp struct {
	lines []string
	done  chan error
}

type Card struct {
	ID        string    `json:"id"`
	Session   string    `json:"session"`
	Project   string    `json:"project"`
	RulesFile string    `json:"rulesFile"`
	Kind      string    `json:"kind"` // read, write, connect, hosts
	Target    string    `json:"target"`
	Cmd       string    `json:"cmd"`
	Count     int       `json:"count"`
	Last      time.Time `json:"last"`
	Learned   bool      `json:"learned"`
	Waiting   int       `json:"waiting"` // requests/lookups paused on this card
	Options   []string  `json:"options"`
	Note      string    `json:"note,omitempty"`
	waiters   []chan bool
}

type Daemon struct {
	mu       sync.Mutex
	sessions map[string]*Session
	cards    map[string]*Card // key: rulesFile|kind|target
	store    *policy.Store
	events   *api.Broadcaster
	jobs     map[string]*Job // brokered command requests waiting for the host
}

func sessionsDir() string { return filepath.Join(system.StateDir(), "sessions") }

// RunDaemon serves the daemon API on its Unix socket until killed.
func RunDaemon() error {
	if err := os.MkdirAll(sessionsDir(), 0o700); err != nil {
		return err
	}
	if err := os.Chmod(system.StateDir(), 0o700); err != nil {
		return err
	}
	_ = os.Remove(system.DaemonSocket())
	ln, err := net.Listen("unix", system.DaemonSocket())
	if err != nil {
		return err
	}
	_ = os.Chmod(system.DaemonSocket(), 0o600)
	_ = os.WriteFile(filepath.Join(system.StateDir(), "daemon.pid"), []byte(strconv.Itoa(os.Getpid())), 0o600)
	d := &Daemon{sessions: map[string]*Session{}, cards: map[string]*Card{}, store: policy.NewStore(), events: api.NewBroadcaster()}
	d.adoptSessions()
	go d.reap()
	log.Printf("sydguard daemon %s listening on %s", system.Version(), system.DaemonSocket())
	return (&http.Server{Handler: d.routes(), ReadHeaderTimeout: 10 * time.Second}).Serve(ln)
}

// adoptSessions re-attaches sessions that survived a daemon restart. Their
// Syd policy is unchanged; proxies and DNS servers restart on the same ports.
func (d *Daemon) adoptSessions() {
	files, _ := filepath.Glob(filepath.Join(sessionsDir(), "*.json"))
	for _, f := range files {
		if strings.HasSuffix(f, ".dns.json") {
			continue
		}
		var s Session
		data, err := os.ReadFile(f)
		if err != nil || json.Unmarshal(data, &s) != nil || !system.Alive(s.PID) || system.SafeText(s.IPC) != nil || system.SafePath(s.RulesFile) != nil {
			removeSessionFiles(s.ID)
			continue
		}
		if !s.Network {
			log.Printf("session %s predates isolated networking; stop and restart this agent", s.ID)
			continue
		}
		if err := d.startProxy(&s); err != nil {
			log.Printf("adopt %s: %v", s.ID, err)
			continue
		}
		if err := d.startDNS(&s); err != nil {
			d.stopServers(&s)
			log.Printf("adopt %s dns: %v", s.ID, err)
			continue
		}
		if err := d.startNetwork(&s); err != nil {
			d.stopServers(&s)
			log.Printf("adopt %s network: %v", s.ID, err)
			continue
		}
		s.Status = statusApplied
		d.startQueue(&s)
		d.sessions[s.ID] = &s
		if err := d.attachNetwork(&s); err != nil {
			s.Status, s.LastError = statusUnknown, err.Error()
			d.stopServers(&s)
		}
		log.Printf("adopted session %s (%s)", s.ID, s.Project)
	}
}

func removeSessionFiles(id string) {
	if id == "" || strings.ContainsAny(id, "/.") {
		return
	}
	for _, ext := range []string{".json", ".syd-3", ".batch", ".resolv", ".dns.json", ".dns.json.tmp", ".tun.sock"} {
		_ = os.Remove(filepath.Join(sessionsDir(), id+ext))
	}
}

// reap ends sessions whose launcher died without saying goodbye.
func (d *Daemon) reap() {
	for range time.Tick(5 * time.Second) {
		d.mu.Lock()
		for id, s := range d.sessions {
			if !system.Alive(s.PID) {
				d.endLocked(id)
			}
		}
		d.mu.Unlock()
	}
}

func (d *Daemon) routes() http.Handler {
	mux := http.NewServeMux()
	api.Handle(mux, "GET /api/ping", func(*http.Request) (any, error) { return map[string]string{"version": system.Version()}, nil })
	api.Handle(mux, "GET /api/state", func(*http.Request) (any, error) { return d.state(), nil })
	mux.HandleFunc("GET /api/events", d.events.Serve)
	d.jobRoutes(mux)
	edit := func(pattern string, fn func(api.EditReq) (any, error)) {
		api.Handle(mux, pattern, func(r *http.Request) (any, error) {
			var req api.EditReq
			if err := api.Decode(r, &req); err != nil {
				return nil, err
			}
			defer d.events.Notify()
			return fn(req)
		})
	}
	edit("POST /api/allow", d.allow)
	edit("POST /api/remove", d.remove)
	edit("POST /api/dismiss", func(req api.EditReq) (any, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		for k, c := range d.cards {
			if c.ID == req.Card || (req.Card == "learned" && c.Learned) {
				d.resolveLocked(k, false)
			}
		}
		return map[string]any{}, nil
	})
	edit("POST /api/trust", func(req api.EditReq) (any, error) {
		if err := system.SafePath(req.File); err != nil {
			return nil, err
		}
		before, after, err := d.store.TrustCurrent(req.File)
		if err != nil {
			return nil, err
		}
		return map[string]any{"saved": req.File, "sessions": d.applyChange(req.File, before, after)}, nil
	})
	edit("POST /api/forget", func(req api.EditReq) (any, error) {
		if err := system.SafePath(req.File); err != nil {
			return nil, err
		}
		if len(d.sessionsFor(req.File)) > 0 {
			return nil, errors.New("an agent is using these rules; stop it first")
		}
		return map[string]any{}, policy.Forget(req.File)
	})
	// When the UI runs on the VM host it owns the global rules and mirrors them here.
	api.Handle(mux, "POST /api/global", func(r *http.Request) (any, error) {
		var req struct{ Rules policy.Rules }
		if err := api.Decode(r, &req); err != nil {
			return nil, err
		}
		clean, err := policy.CleanRules(req.Rules)
		if err != nil {
			return nil, err
		}
		before, after, err := d.store.Replace(system.GlobalRulesPath(), clean)
		if err != nil {
			return nil, err
		}
		defer d.events.Notify()
		return map[string]any{"sessions": d.applyChange("", before, after)}, nil
	})
	api.Handle(mux, "POST /internal/session", func(r *http.Request) (any, error) {
		var s Session
		if err := api.Decode(r, &s); err != nil {
			return nil, err
		}
		defer d.events.Notify()
		return d.register(&s)
	})
	api.Handle(mux, "POST /internal/events", func(r *http.Request) (any, error) {
		var req struct {
			Session string
			Lines   []string
		}
		if err := api.Decode(r, &req); err != nil {
			return nil, err
		}
		if d.syslog(req.Session, req.Lines) {
			d.events.Notify()
		}
		return map[string]any{}, nil
	})
	api.Handle(mux, "POST /internal/started", func(r *http.Request) (any, error) {
		var req struct {
			Session string
			PID     int
		}
		if err := api.Decode(r, &req); err != nil {
			return nil, err
		}
		d.mu.Lock()
		s, ok := d.sessions[req.Session]
		if !ok || req.PID <= 0 {
			d.mu.Unlock()
			return nil, errors.New("bad session start")
		}
		s.SydPID = req.PID
		meta, _ := json.Marshal(s)
		err := os.WriteFile(filepath.Join(sessionsDir(), s.ID+".json"), meta, 0o600)
		d.mu.Unlock()
		if err != nil {
			return nil, err
		}
		if err := d.attachNetwork(s); err != nil {
			d.stopServers(s)
			return nil, err
		}
		return map[string]any{}, nil
	})
	api.Handle(mux, "POST /internal/end", func(r *http.Request) (any, error) {
		var req struct{ Session string }
		if err := api.Decode(r, &req); err != nil {
			return nil, err
		}
		d.mu.Lock()
		d.endLocked(req.Session)
		d.mu.Unlock()
		d.events.Notify()
		return map[string]any{}, nil
	})
	api.Handle(mux, "POST /internal/quit", func(*http.Request) (any, error) {
		go func() { time.Sleep(100 * time.Millisecond); os.Exit(0) }()
		return map[string]any{}, nil
	})
	return mux
}

func (d *Daemon) register(s *Session) (any, error) {
	for _, p := range []string{s.Project, s.Cwd, s.RulesFile} {
		if err := system.SafePath(p); err != nil {
			return nil, err
		}
	}
	if len(s.Cmd) == 0 || s.PID <= 0 {
		return nil, errors.New("bad session")
	}
	for _, a := range s.Cmd {
		if strings.ContainsRune(a, 0) {
			return nil, errors.New("bad argument")
		}
	}
	s.LocalPorts = slices.Compact(slices.Sorted(slices.Values(s.LocalPorts)))
	if len(s.LocalPorts) > 64 {
		return nil, errors.New("at most 64 local ports")
	}
	for _, p := range s.LocalPorts {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("bad local port %d", p)
		}
	}
	if v := d.store.View(s.RulesFile); v.Pending != "" || v.Error != "" {
		return nil, fmt.Errorf("%s isn't trusted (%s); run from a terminal to review it", s.RulesFile, v.Error)
	}
	if !namespacesOK() {
		return nil, errors.New("isolated networking requires user/mount/net namespaces; run `sydguard setup`")
	}
	s.ID = system.NewID()
	s.Network = true
	s.IPC = "@sydguard-" + s.ID + "-" + system.NewID()
	s.Started = time.Now()
	s.Status = statusApplied
	if err := d.startProxy(s); err != nil {
		return nil, err
	}
	registered := false
	defer func() {
		if !registered {
			d.stopServers(s)
			removeSessionFiles(s.ID)
		}
	}()
	if err := d.startDNS(s); err != nil {
		return nil, err
	}
	if err := d.startNetwork(s); err != nil {
		return nil, err
	}
	s.Overlays = overlayDirs(s.Project, s.OverlayNames)
	in := policy.ProfileInput{
		Project: s.Project, Rules: []policy.Rules{d.store.Get(system.GlobalRulesPath()), d.store.Get(s.RulesFile)},
		Launch: s.Launch, Protect: policy.ProtectedFor(s.Project, s.RulesFile, system.GlobalRulesPath()), ProxyPort: s.ProxyPort,
		IPC: s.IPC, Learn: s.Learn, LocalPorts: s.LocalPorts, PassEnv: s.EnvNames, Network: true,
	}
	if s.DNSAddr != "" {
		resolv := filepath.Join(sessionsDir(), s.ID+".resolv")
		host, _, _ := net.SplitHostPort(s.DNSAddr)
		if err := os.WriteFile(resolv, []byte("nameserver "+host+"\noptions timeout:5 attempts:2 ndots:1\n"), 0o644); err != nil {
			return nil, err
		}
		in.DNS, in.ResolvConf = s.DNSAddr, resolv
	}
	for _, o := range s.Overlays {
		in.Overlays = append(in.Overlays, policy.Overlay{Source: overlaySource(s.Project, o), Target: filepath.Join(s.Project, o)})
	}
	profile, err := policy.CompileProfile(in)
	if err != nil {
		d.stopServers(s)
		return nil, err
	}
	path := filepath.Join(sessionsDir(), s.ID+".syd-3")
	meta, _ := json.Marshal(s)
	if err := os.WriteFile(path, []byte(profile), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(sessionsDir(), s.ID+".json"), meta, 0o600); err != nil {
		return nil, err
	}
	d.startQueue(s)
	d.mu.Lock()
	d.sessions[s.ID] = s
	registered = true
	d.mu.Unlock()
	log.Printf("session %s started: %s in %s (rules %s, dns %q, overlays %v)", s.ID, strings.Join(s.Cmd, " "), s.Project, s.RulesFile, s.DNSAddr, s.Overlays)
	return map[string]any{"id": s.ID, "profile": path, "proxyPort": s.ProxyPort, "dns": s.DNSAddr != "", "overlays": s.Overlays}, nil
}

func (d *Daemon) stopServers(s *Session) {
	if s.proxy != nil {
		_ = s.proxy.Close()
	}
	if s.network != nil {
		s.network.close()
	}
}

func (d *Daemon) endLocked(id string) {
	s, ok := d.sessions[id]
	if !ok {
		return
	}
	delete(d.sessions, id)
	d.stopServers(s)
	close(s.queue)
	var learned []*Card
	for k, c := range d.cards {
		if c.Session != id {
			continue
		}
		if c.Learned && s.Learn && len(c.Options) > 0 {
			learned = append(learned, c)
		}
		d.resolveLocked(k, false)
	}
	if len(learned) > 0 {
		// Learn runs save what they used, so the next normal run just works.
		_, _, err := d.store.Edit(s.RulesFile, func(r *policy.Rules) error {
			prot := policy.ProtectedFor(s.Project, s.RulesFile)
			for _, c := range learned {
				if n, err := policy.Normalize(c.Kind, c.Options[0]); err == nil && prot.Check(c.Kind, n) == nil {
					_ = policy.AddRule(c.Kind, n)(r)
				}
			}
			return nil
		})
		log.Printf("session %s: learned %d rules into %s (err=%v)", id, len(learned), s.RulesFile, err)
	}
	removeSessionFiles(id)
	log.Printf("session %s ended", id)
}

// Live updates --------------------------------------------------------------

func (d *Daemon) startQueue(s *Session) {
	s.queue = make(chan applyOp, 64)
	go func() {
		for op := range s.queue {
			d.mu.Lock()
			status := s.Status
			if status != statusUnknown {
				s.Status = statusUpdating
			}
			d.mu.Unlock()
			if status == statusUnknown {
				op.done <- errors.New("session policy state unknown after an earlier failed update; restart the agent to resync")
				continue
			}
			err := sydLoad(s, op.lines)
			d.mu.Lock()
			if err != nil {
				s.Status, s.LastError = statusUnknown, err.Error()
			} else {
				s.Status, s.LastError = statusApplied, ""
			}
			d.mu.Unlock()
			d.events.Notify()
			op.done <- err
		}
	}()
}

type applyResult struct {
	Session string `json:"session"`
	Applied bool   `json:"applied"`
	Error   string `json:"error,omitempty"`
}

// pushOne applies Syd commands to one session, followed by its protection
// denies, as one atomic batch. Never called with d.mu held.
func (d *Daemon) pushOne(s *Session, cmds []string) applyResult {
	lines := append(slices.Clone(cmds), policy.ProtectedFor(s.Project, s.RulesFile, system.GlobalRulesPath()).Commands()...)
	done := make(chan error, 1)
	res := applyResult{Session: s.ID}
	func() {
		defer func() {
			if recover() != nil { // queue closed: session ended
				done <- errors.New("session ended")
			}
		}()
		s.queue <- applyOp{lines: lines, done: done}
	}()
	select {
	case err := <-done:
		res.Applied = err == nil
		if err != nil {
			res.Error = err.Error()
		}
	case <-time.After(8 * time.Second):
		res.Error = "timed out; state unknown"
	}
	return res
}

// sydLoad sends a batch to Syd's IPC as one "load" of a passed file
// descriptor, so a grant and its protection denies apply together.
func sydLoad(s *Session, lines []string) error {
	for _, l := range lines {
		if system.SafeText(l) != nil {
			return fmt.Errorf("refusing unsafe command %q", l)
		}
	}
	path := filepath.Join(sessionsDir(), s.ID+".batch")
	_ = os.Remove(path)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close(); _ = os.Remove(path) }()
	if _, err := f.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		return err
	}
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}
	if s.DNSAddr != "" || len(s.Overlays) > 0 {
		return loadViaNamespace(s, path)
	}
	return LoadFD(s.IPC, f)
}

// loadViaNamespace runs `sydguard ipc-load` inside the session's user and PID
// namespaces: Syd's IPC only accepts peers whose PID it can see.
func loadViaNamespace(s *Session, batch string) error {
	if s.SydPID <= 0 || !system.Alive(s.SydPID) {
		return errors.New("syd process unknown; state unknown")
	}
	exe, err := os.Executable()
	if err != nil || strings.HasSuffix(exe, " (deleted)") {
		exe = filepath.Join(system.Home(), ".local", "bin", "sydguard")
	}
	ns := fmt.Sprintf("/proc/%d/ns/", s.SydPID)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nsenter", "--user="+ns+"user", "--pid="+ns+"pid_for_children",
		"--preserve-credentials", "--", exe, "ipc-load", s.IPC, batch).CombinedOutput()
	if err != nil {
		return fmt.Errorf("syd ipc (via namespace): %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// LoadFD sends an open batch file to Syd's IPC socket as one "load" and
// checks the acknowledgment.
func LoadFD(ipc string, f *os.File) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", ipc)
	if err != nil {
		return fmt.Errorf("syd ipc: %w", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("syd ipc: not a unix socket")
	}
	if _, _, err := uc.WriteMsgUnix([]byte("load\n"), syscall.UnixRights(int(f.Fd())), nil); err != nil {
		return fmt.Errorf("syd ipc send: %w", err)
	}
	line, err := bufio.NewReader(io.LimitReader(conn, 4096)).ReadString('\n')
	if err != nil && line == "" {
		return fmt.Errorf("syd ipc: no reply (state unknown): %w", err)
	}
	var ack struct {
		Err int    `json:"err"`
		Msg string `json:"msg"`
	}
	if json.Unmarshal([]byte(line), &ack) != nil || ack.Err != 0 || ack.Msg != "ACK" {
		return fmt.Errorf("syd rejected update: %s", strings.TrimSpace(line))
	}
	return nil
}

func (d *Daemon) sessionsFor(rulesFile string) []*Session {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []*Session
	for _, s := range d.sessions {
		if rulesFile == "" || s.RulesFile == rulesFile {
			out = append(out, s)
		}
	}
	return out
}

func (d *Daemon) target(req api.EditReq) (string, policy.Protection, error) {
	if req.Scope == "global" {
		prot := policy.ProtectedFor("", system.GlobalRulesPath())
		for _, s := range d.sessionsFor("") {
			p := policy.ProtectedFor(s.Project, s.RulesFile)
			prot.NoWrite = append(prot.NoWrite, p.NoWrite...)
		}
		return system.GlobalRulesPath(), prot, nil
	}
	file := req.File
	if file == "" && req.Card != "" {
		d.mu.Lock()
		for _, c := range d.cards {
			if c.ID == req.Card {
				file = c.RulesFile
			}
		}
		d.mu.Unlock()
	}
	if err := system.SafePath(file); err != nil {
		return "", policy.Protection{}, fmt.Errorf("no rules file: %w", err)
	}
	return file, policy.ProtectedFor(policy.ProjectOfRulesFile(file), file, system.GlobalRulesPath()), nil
}

func scopeFile(req api.EditReq, file string) string {
	if req.Scope == "global" {
		return ""
	}
	return file
}

func (d *Daemon) allow(req api.EditReq) (any, error) {
	pattern, err := policy.Normalize(req.Kind, req.Pattern)
	if err != nil {
		return nil, err
	}
	file, prot, err := d.target(req)
	if err != nil {
		return nil, err
	}
	if err := prot.Check(req.Kind, pattern); err != nil {
		return nil, err
	}
	before, after, err := d.store.Edit(file, policy.AddRule(req.Kind, pattern))
	if err != nil {
		return nil, err
	}
	return map[string]any{"saved": file, "sessions": d.applyChange(scopeFile(req, file), before, after)}, nil
}

func (d *Daemon) remove(req api.EditReq) (any, error) {
	file, _, err := d.target(req)
	if err != nil {
		return nil, err
	}
	before, after, err := d.store.Edit(file, policy.RemoveRule(req.Kind, req.Pattern))
	if err != nil {
		return nil, err
	}
	sessions := d.sessionsFor(scopeFile(req, file))
	out := map[string]any{"saved": file, "sessions": d.applyChange(scopeFile(req, file), before, after)}
	if note := d.stillAllowedBy(sessions, req.Kind, req.Pattern); note != "" {
		out["note"] = note
	}
	return out, nil
}

// applyChange pushes the difference between two versions of a rules file
// ("" = global) to the affected sessions: path/connect rules directly, host
// rules via the IPs their DNS answers granted. Then it releases covered cards.
func (d *Daemon) applyChange(rulesFile string, before, after policy.Rules) []applyResult {
	sessions := d.sessionsFor(rulesFile)
	results := make([]applyResult, len(sessions))
	var wg sync.WaitGroup
	for i, s := range sessions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmds := policy.DiffCommands(before, after)
			if s.network != nil && networkRulesRemoved(before, after) {
				s.network.revoke()
			}
			if len(cmds) == 0 {
				results[i] = applyResult{Session: s.ID, Applied: true}
				return
			}
			results[i] = d.pushOne(s, cmds)
		}()
	}
	wg.Wait()
	d.resolveAdded(before, after, rulesFile)
	return results
}

// stillAllowedBy explains when a removed path rule is still covered by another.
func (d *Daemon) stillAllowedBy(sessions []*Session, kind, pattern string) string {
	if kind != "read" && kind != "write" {
		return ""
	}
	probe := policy.LiteralPrefix(system.ExpandHome(pattern))
	for _, s := range sessions {
		var pats []string
		for _, r := range []policy.Rules{d.store.Get(system.GlobalRulesPath()), d.store.Get(s.RulesFile)} {
			pats = append(pats, r.Write...)
			if kind == "read" {
				pats = append(pats, r.Read...)
			}
		}
		for _, b := range policy.Baseline(s.Project) {
			if b.Kind == "write" || kind == "read" {
				pats = append(pats, b.Pattern)
			}
		}
		for _, p := range pats {
			if p != pattern && policy.MatchPath(p, probe) {
				return fmt.Sprintf("still allowed by %s", p)
			}
		}
	}
	return ""
}

// resolveAdded releases cards (and paused requests) covered by rules that
// were added between before and after. rulesFile "" = global.
func (d *Daemon) resolveAdded(before, after policy.Rules, rulesFile string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, kind := range policy.Kinds {
		for _, p := range *after.List(kind) {
			if slices.Contains(*before.List(kind), p) {
				continue
			}
			for k, c := range d.cards {
				if (rulesFile == "" || c.RulesFile == rulesFile) && covers(kind, p, c) {
					d.resolveLocked(k, kind != "ignore")
				}
			}
		}
	}
}

func covers(kind, pattern string, c *Card) bool {
	switch kind {
	case "ignore":
		return policy.Ignored([]policy.Rules{{Ignore: []string{pattern}}}, c.Kind, c.Target)
	case "hosts":
		if c.Kind != "hosts" {
			return false
		}
		h, err := policy.ParseHostRule(pattern)
		if err != nil {
			return false
		}
		scheme, rest, _ := strings.Cut(c.Target, "://")
		host, port, err := net.SplitHostPort(rest)
		if err != nil { // DNS card: no port yet
			return h.MatchName(rest)
		}
		return h.Match(scheme, host, port)
	case "connect":
		return c.Kind == "connect" && pattern == c.Target
	case "write":
		return (c.Kind == "write" || c.Kind == "read") && policy.MatchPath(pattern, c.Target)
	case "read":
		return c.Kind == "read" && policy.MatchPath(pattern, c.Target)
	}
	return false
}

// Syd log -> cards ----------------------------------------------------------

type sydEvent struct {
	Ctx  string          `json:"ctx"`
	Cap  json.RawMessage `json:"cap"`
	Act  string          `json:"act"`
	Path string          `json:"path"`
	Addr string          `json:"addr"`
	Unix string          `json:"unix"`
	Type string          `json:"type"`
	Cmd  string          `json:"cmd"`
}

var writeLike = []string{"write", "create", "delete", "rename", "truncate", "symlink", "mkdir", "rmdir", "chmod", "chattr", "chown", "chgrp", "utime", "mkfifo", "mktemp", "mkdev"}

func (e sydEvent) caps() []string {
	var one string
	if json.Unmarshal(e.Cap, &one) == nil {
		return []string{one}
	}
	var many []string
	_ = json.Unmarshal(e.Cap, &many)
	return many
}

// noise: lookups that are denied harmlessly and would only clutter the UI.
func noise(p string) bool {
	for _, n := range []string{"/proc/", "/sys/", "/dev/", "/run/user/"} {
		if strings.HasPrefix(p, n) {
			return true
		}
	}
	return strings.HasPrefix(p, "!")
}

// syslog turns Syd access-violation log lines into cards. Reports whether
// anything visible changed.
func (d *Daemon) syslog(sessionID string, lines []string) bool {
	d.mu.Lock()
	s, ok := d.sessions[sessionID]
	d.mu.Unlock()
	if !ok {
		return false
	}
	rules := []policy.Rules{d.store.Get(system.GlobalRulesPath()), d.store.Get(s.RulesFile)}
	prot := policy.ProtectedFor(s.Project, s.RulesFile, system.GlobalRulesPath())
	d.mu.Lock()
	defer d.mu.Unlock()
	changed := false
	for _, line := range lines {
		var e sydEvent
		if json.Unmarshal([]byte(line), &e) != nil || e.Ctx != "access" || (e.Act != "deny" && e.Act != "warn") {
			continue
		}
		caps := e.caps()
		kind, target, note := "", "", ""
		switch {
		case slices.Contains(caps, "net/connect") && e.Addr != "":
			kind, target = "connect", strings.TrimPrefix(strings.TrimPrefix(e.Addr, "tcp!"), "udp!")
			// Internet flows are mediated by the isolated stack, not Syd.
		case slices.Contains(caps, "net/connect") && e.Unix != "" && !strings.HasPrefix(e.Unix, "@"):
			kind, target = "connect", e.Unix
		case e.Path == "" || noise(e.Path):
			continue
		case slices.ContainsFunc(caps, func(c string) bool { return slices.Contains(writeLike, c) }):
			kind, target = "write", e.Path
		case slices.ContainsFunc(caps, func(c string) bool { return strings.HasPrefix(c, "read") || c == "exec" || c == "chdir" || c == "stat" }):
			kind, target = "read", e.Path
		default:
			continue
		}
		if system.SafeText(target) != nil || (strings.HasPrefix(target, "/") && system.SafePath(target) != nil) {
			continue // never turn unprintable names into rules
		}
		if (kind == "read" || kind == "write") && prot.Check(kind, target) != nil {
			continue // protected paths are never grantable, so don't ask
		}
		if policy.Ignored(rules, kind, target) {
			continue
		}
		learned := e.Act == "warn"
		dir := e.Type == "dir"
		if learned && (kind == "read" || kind == "write") {
			target, dir = policy.LearnRoot(target), true
		}
		d.addCardLocked(s, kind, target, e.Cmd, learned, dir, note)
		changed = true
	}
	return changed
}

func (d *Daemon) addCardLocked(s *Session, kind, target, cmd string, learned, dir bool, note string) *Card {
	key := s.RulesFile + "|" + kind + "|" + target
	if c, ok := d.cards[key]; ok {
		c.Count++
		c.Last = time.Now()
		return c
	}
	if len(d.cards) > 2000 {
		return nil
	}
	c := &Card{
		ID: system.NewID(), Session: s.ID, Project: s.Project, RulesFile: s.RulesFile, Kind: kind, Target: target,
		Cmd: truncate(cmd, 200), Count: 1, Last: time.Now(), Learned: learned, Note: note,
	}
	switch kind {
	case "read", "write":
		c.Options = policy.Suggestions(target, dir)
		if !learned && !dir && note == "" {
			c.Note = "denied — the agent saw an error; it succeeds on retry once applied"
		}
	case "hosts":
		scheme, rest, _ := strings.Cut(target, "://")
		if host, port, err := net.SplitHostPort(rest); err == nil {
			c.Options = policy.HostSuggestions(scheme, host, port)
		} else { // DNS lookup: no port yet; raw access needs a tcp:// rule
			c.Options = append([]string{"tcp://" + rest}, policy.HostSuggestions("", rest, "")...)
		}
	default:
		c.Options = []string{target}
		c.Note = "raw network target (the tool bypassed the proxy and DNS)"
	}
	d.cards[key] = c
	return c
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func (d *Daemon) resolveLocked(key string, allowed bool) {
	c := d.cards[key]
	for _, w := range c.waiters {
		w <- allowed
	}
	delete(d.cards, key)
}

// waitCard registers a waiter on a card and blocks until a decision, ctx end
// or timeout. Returns true only for an explicit approval.
func (d *Daemon) waitCard(ctx context.Context, c *Card, timeout time.Duration) bool {
	ch := make(chan bool, 1)
	c.waiters = append(c.waiters, ch)
	d.mu.Unlock()
	d.events.Notify()
	select {
	case ok := <-ch:
		return ok
	case <-ctx.Done():
	case <-time.After(timeout):
	}
	d.mu.Lock()
	for i, w := range c.waiters {
		if w == ch {
			c.waiters = append(c.waiters[:i], c.waiters[i+1:]...)
			break
		}
	}
	d.mu.Unlock()
	d.events.Notify()
	return false
}

// State ---------------------------------------------------------------------

type rulesView struct {
	policy.RuleFile
	Project  string            `json:"project"`
	Baseline []policy.BaseRule `json:"baseline,omitempty"`
	Sessions []string          `json:"sessions"`
}

func (d *Daemon) state() map[string]any {
	d.mu.Lock()
	sessions := make([]Session, 0, len(d.sessions))
	files := map[string]string{} // rules file -> project
	for _, s := range d.sessions {
		view := *s
		if s.network != nil {
			view.Connections = s.network.snapshot()
		}
		sessions = append(sessions, view)
		files[s.RulesFile] = s.Project
	}
	cards := make([]Card, 0, len(d.cards))
	for _, c := range d.cards {
		c.Waiting = len(c.waiters)
		cards = append(cards, *c)
	}
	d.mu.Unlock()
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].Started.Before(sessions[j].Started) })
	sort.Slice(cards, func(i, j int) bool { return cards[i].Last.After(cards[j].Last) })
	for _, f := range policy.KnownRulesFiles() {
		if _, ok := files[f]; !ok && f != system.GlobalRulesPath() {
			files[f] = policy.ProjectOfRulesFile(f)
		}
	}
	views := []rulesView{}
	for f, p := range files {
		v := rulesView{RuleFile: d.store.View(f), Project: p, Sessions: []string{}}
		if p != "" {
			v.Baseline = policy.Baseline(p)
		}
		for _, s := range sessions {
			if s.RulesFile == f {
				v.Sessions = append(v.Sessions, s.ID)
			}
		}
		views = append(views, v)
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Path < views[j].Path })
	return map[string]any{
		"version": system.Version(), "sessions": sessions, "cards": cards, "files": views,
		"global": d.store.View(system.GlobalRulesPath()), "namespaces": namespacesOK(),
	}
}

// Client --------------------------------------------------------------------

// Call talks to the local daemon.
func Call(method, path string, in, out any) error {
	return api.Call(api.UnixClient(system.DaemonSocket(), 15*time.Second), method, path, in, out)
}

// EnsureDaemon starts the background daemon if needed (restarting it when the
// binary changed). Returns true when a new daemon was started.
func EnsureDaemon() (bool, error) {
	var ping struct{ Version string }
	if err := Call("GET", "/api/ping", nil, &ping); err == nil {
		if ping.Version == system.Version() {
			return false, nil
		}
		_ = Call("POST", "/internal/quit", nil, nil)
		time.Sleep(400 * time.Millisecond)
	}
	if err := os.MkdirAll(system.StateDir(), 0o700); err != nil {
		return false, err
	}
	if err := system.SpawnDetached(filepath.Join(system.StateDir(), "daemon.log"), "daemon"); err != nil {
		return false, err
	}
	for range 50 {
		time.Sleep(100 * time.Millisecond)
		if Call("GET", "/api/ping", nil, &ping) == nil && ping.Version == system.Version() {
			return true, nil
		}
	}
	return false, errors.New("daemon did not start; see " + filepath.Join(system.StateDir(), "daemon.log"))
}
