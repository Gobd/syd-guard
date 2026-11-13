package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The guest daemon: one per Linux machine/VM, outside the sandbox. It owns the
// sessions, their proxies and live Syd updates, and listens only on a Unix
// socket in a directory the sandbox can't touch.

func daemonSocket() string    { return filepath.Join(stateDir(), "daemon.sock") }
func globalRulesPath() string { return filepath.Join(configDir(), "global.json") }

const (
	statusApplied  = "applied"
	statusUpdating = "updating"
	statusUnknown  = "unknown" // a live update failed or timed out; edits stop
)

type Session struct {
	ID        string    `json:"id"`
	Project   string    `json:"project"`
	RulesFile string    `json:"rulesFile"`
	Cwd       string    `json:"cwd"`
	Cmd       []string  `json:"cmd"`
	Learn     bool      `json:"learn"`
	PID       int       `json:"pid"`
	IPC       string    `json:"ipc"`
	ProxyPort int       `json:"proxyPort"`
	Started   time.Time `json:"started"`
	Launch    []string  `json:"launch"`
	Status    string    `json:"status"`
	LastError string    `json:"lastError,omitempty"`
	proxy     *http.Server
	queue     chan applyOp
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
	Waiting   int       `json:"waiting"` // proxied requests paused on this card
	Options   []string  `json:"options"`
	Note      string    `json:"note,omitempty"`
	waiters   []chan bool
}

type Daemon struct {
	mu       sync.Mutex
	sessions map[string]*Session
	cards    map[string]*Card // key: rulesFile|kind|target
	store    *ruleStore
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func runDaemon() error {
	if err := os.MkdirAll(filepath.Join(stateDir(), "sessions"), 0o700); err != nil {
		return err
	}
	if err := os.Chmod(stateDir(), 0o700); err != nil {
		return err
	}
	_ = os.Remove(daemonSocket())
	ln, err := net.Listen("unix", daemonSocket())
	if err != nil {
		return err
	}
	_ = os.Chmod(daemonSocket(), 0o600)
	d := &Daemon{sessions: map[string]*Session{}, cards: map[string]*Card{}, store: newRuleStore()}
	d.adoptSessions()
	go d.reap()
	log.Printf("sydguard daemon %s listening on %s", selfVersion(), daemonSocket())
	return (&http.Server{Handler: d.routes(), ReadHeaderTimeout: 10 * time.Second}).Serve(ln)
}

// adoptSessions re-attaches sessions that survived a daemon restart. Their
// Syd policy is unchanged; status is Unknown until the next successful update.
func (d *Daemon) adoptSessions() {
	files, _ := filepath.Glob(filepath.Join(stateDir(), "sessions", "*.json"))
	for _, f := range files {
		var s Session
		data, err := os.ReadFile(f)
		if err != nil || json.Unmarshal(data, &s) != nil || !alive(s.PID) || safeText(s.IPC) != nil || safePath(s.RulesFile) != nil {
			d.removeSessionFiles(s.ID)
			continue
		}
		if err := d.startProxy(&s); err != nil {
			log.Printf("adopt %s: %v", s.ID, err)
			continue
		}
		s.Status = statusApplied
		d.startQueue(&s)
		d.sessions[s.ID] = &s
		log.Printf("adopted session %s (%s)", s.ID, s.Project)
	}
}

func (d *Daemon) removeSessionFiles(id string) {
	if id == "" || strings.ContainsAny(id, "/.") {
		return
	}
	for _, ext := range []string{".json", ".syd-3", ".batch"} {
		_ = os.Remove(filepath.Join(stateDir(), "sessions", id+ext))
	}
}

// reap ends sessions whose launcher died without saying goodbye.
func (d *Daemon) reap() {
	for range time.Tick(5 * time.Second) {
		d.mu.Lock()
		for id, s := range d.sessions {
			if !alive(s.PID) {
				d.endLocked(id)
			}
		}
		d.mu.Unlock()
	}
}

type apiFunc func(r *http.Request) (any, error)

func jsonAPI(mux *http.ServeMux, pattern string, h apiFunc) {
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		out, err := h(r)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			out = map[string]string{"error": err.Error()}
		}
		_ = json.NewEncoder(w).Encode(out)
	})
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 4<<20))
	return dec.Decode(v)
}

type editReq struct {
	VM      string `json:"vm"`
	Card    string `json:"card"`
	Scope   string `json:"scope"` // "global" or "rules"
	File    string `json:"file"`  // rules file for scope "rules"
	Kind    string `json:"kind"`
	Pattern string `json:"pattern"`
}

func (d *Daemon) routes() http.Handler {
	mux := http.NewServeMux()
	jsonAPI(mux, "GET /api/ping", func(*http.Request) (any, error) { return map[string]string{"version": selfVersion()}, nil })
	jsonAPI(mux, "GET /api/state", func(*http.Request) (any, error) { return d.state(), nil })
	jsonAPI(mux, "POST /api/allow", func(r *http.Request) (any, error) {
		var req editReq
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		return d.allow(req)
	})
	jsonAPI(mux, "POST /api/remove", func(r *http.Request) (any, error) {
		var req editReq
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		return d.remove(req)
	})
	jsonAPI(mux, "POST /api/dismiss", func(r *http.Request) (any, error) {
		var req editReq
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		for k, c := range d.cards {
			if c.ID == req.Card || (req.Card == "learned" && c.Learned) {
				d.resolveLocked(k, false)
			}
		}
		return map[string]any{}, nil
	})
	jsonAPI(mux, "POST /api/trust", func(r *http.Request) (any, error) {
		var req editReq
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		if err := safePath(req.File); err != nil {
			return nil, err
		}
		before, after, err := d.store.trustCurrent(req.File)
		if err != nil {
			return nil, err
		}
		results := d.push(d.sessionsFor(req.File), diffCommands(before, after))
		d.resolveAdded(before, after, req.File)
		return map[string]any{"saved": req.File, "sessions": results}, nil
	})
	// The Mac UI owns the global rules and mirrors them to every VM.
	jsonAPI(mux, "POST /api/global", func(r *http.Request) (any, error) {
		var req struct{ Rules Rules }
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		clean, err := cleanRules(req.Rules)
		if err != nil {
			return nil, err
		}
		before, after, err := d.store.replace(globalRulesPath(), clean)
		if err != nil {
			return nil, err
		}
		results := d.push(d.sessionsFor(""), diffCommands(before, after))
		d.resolveAdded(before, after, "")
		return map[string]any{"sessions": results}, nil
	})
	jsonAPI(mux, "POST /internal/session", func(r *http.Request) (any, error) {
		var s Session
		if err := decode(r, &s); err != nil {
			return nil, err
		}
		return d.register(&s)
	})
	jsonAPI(mux, "POST /internal/events", func(r *http.Request) (any, error) {
		var req struct {
			Session string
			Lines   []string
		}
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		d.events(req.Session, req.Lines)
		return map[string]any{}, nil
	})
	jsonAPI(mux, "POST /internal/end", func(r *http.Request) (any, error) {
		var req struct{ Session string }
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		d.mu.Lock()
		d.endLocked(req.Session)
		d.mu.Unlock()
		return map[string]any{}, nil
	})
	jsonAPI(mux, "POST /internal/quit", func(*http.Request) (any, error) {
		go func() { time.Sleep(100 * time.Millisecond); os.Exit(0) }()
		return map[string]any{}, nil
	})
	return mux
}

func cleanRules(r Rules) (Rules, error) {
	var out Rules
	for _, k := range kinds {
		for _, p := range *r.list(k) {
			n, err := normalize(k, p)
			if err != nil {
				return out, err
			}
			*out.list(k) = append(*out.list(k), n)
		}
	}
	return out, nil
}

func (d *Daemon) register(s *Session) (any, error) {
	for _, p := range []string{s.Project, s.Cwd, s.RulesFile} {
		if err := safePath(p); err != nil {
			return nil, err
		}
	}
	if len(s.Cmd) == 0 || s.PID <= 0 {
		return nil, errors.New("bad session")
	}
	for _, a := range s.Cmd {
		if strings.ContainsAny(a, "\x00") {
			return nil, errors.New("bad argument")
		}
	}
	if v := d.store.view(s.RulesFile); v.Pending != "" || v.Error != "" {
		return nil, fmt.Errorf("%s isn't trusted (%s); run from a terminal to review it", s.RulesFile, v.Error)
	}
	s.ID = newID()
	s.IPC = "@sydguard-" + s.ID + "-" + newID()
	s.Started = time.Now()
	s.Status = statusApplied
	prot := protectedFor(s.Project, s.RulesFile, globalRulesPath())
	if err := d.startProxy(s); err != nil {
		return nil, err
	}
	profile, err := compileProfile(profileInput{Project: s.Project, Rules: []Rules{d.store.get(globalRulesPath()), d.store.get(s.RulesFile)},
		Launch: s.Launch, Protect: prot, ProxyPort: s.ProxyPort, IPC: s.IPC, Learn: s.Learn})
	if err != nil {
		_ = s.proxy.Close()
		return nil, err
	}
	dir := filepath.Join(stateDir(), "sessions")
	path := filepath.Join(dir, s.ID+".syd-3")
	meta, _ := json.Marshal(s)
	if err := os.WriteFile(path, []byte(profile), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, s.ID+".json"), meta, 0o600); err != nil {
		return nil, err
	}
	d.startQueue(s)
	d.mu.Lock()
	d.sessions[s.ID] = s
	d.mu.Unlock()
	log.Printf("session %s started: %s in %s (rules %s)", s.ID, strings.Join(s.Cmd, " "), s.Project, s.RulesFile)
	return map[string]any{"id": s.ID, "profile": path, "proxyPort": s.ProxyPort}, nil
}

func (d *Daemon) endLocked(id string) {
	s, ok := d.sessions[id]
	if !ok {
		return
	}
	delete(d.sessions, id)
	if s.proxy != nil {
		_ = s.proxy.Close()
	}
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
		_, _, err := d.store.edit(s.RulesFile, func(r *Rules) error {
			prot := protectedFor(s.Project, s.RulesFile)
			for _, c := range learned {
				if n, err := normalize(c.Kind, c.Options[0]); err == nil && prot.check(c.Kind, n) == nil {
					_ = addRule(c.Kind, n)(r)
				}
			}
			return nil
		})
		log.Printf("session %s: learned %d rules into %s (err=%v)", id, len(learned), s.RulesFile, err)
	}
	d.removeSessionFiles(id)
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
			op.done <- err
		}
	}()
}

type applyResult struct {
	Session string `json:"session"`
	Applied bool   `json:"applied"`
	Error   string `json:"error,omitempty"`
}

// push applies Syd commands to sessions, each followed by its protection
// denies, as one atomic batch per session. Never called with d.mu held.
func (d *Daemon) push(sessions []*Session, cmds []string) []applyResult {
	results := make([]applyResult, len(sessions))
	if len(cmds) == 0 {
		for i, s := range sessions {
			results[i] = applyResult{Session: s.ID, Applied: true}
		}
		return results
	}
	var wg sync.WaitGroup
	for i, s := range sessions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lines := append(slices.Clone(cmds), protectedFor(s.Project, s.RulesFile, globalRulesPath()).commands()...)
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
			results[i] = res
		}()
	}
	wg.Wait()
	return results
}

// sydLoad sends a batch to Syd's IPC as one "load" of a passed file
// descriptor, so a grant and its protection denies apply together.
func sydLoad(s *Session, lines []string) error {
	for _, l := range lines {
		if strings.ContainsAny(l, "\n\r") || safeText(l) != nil {
			return fmt.Errorf("refusing unsafe command %q", l)
		}
	}
	path := filepath.Join(stateDir(), "sessions", s.ID+".batch")
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", s.IPC)
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
	line, err := bufio.NewReader(io4k(conn)).ReadString('\n')
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

type limitedReader struct {
	r net.Conn
	n int
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, errors.New("reply too long")
	}
	if len(p) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= n
	return n, err
}

func io4k(c net.Conn) *limitedReader { return &limitedReader{c, 4096} }

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

// projectOfRulesFile guesses the project a rules file belongs to.
func projectOfRulesFile(file string) string {
	dir := filepath.Dir(file)
	if filepath.Base(dir) == rulesDirName {
		return filepath.Dir(dir)
	}
	if filepath.Base(file) == defaultRulesName {
		return dir
	}
	return ""
}

func (d *Daemon) target(req editReq) (string, protection, error) {
	if req.Scope == "global" {
		prot := protectedFor("", globalRulesPath())
		for _, s := range d.sessionsFor("") {
			p := protectedFor(s.Project, s.RulesFile)
			prot.noWrite = append(prot.noWrite, p.noWrite...)
		}
		return globalRulesPath(), prot, nil
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
	if err := safePath(file); err != nil {
		return "", protection{}, fmt.Errorf("no rules file: %w", err)
	}
	return file, protectedFor(projectOfRulesFile(file), file, globalRulesPath()), nil
}

func (d *Daemon) allow(req editReq) (any, error) {
	pattern, err := normalize(req.Kind, req.Pattern)
	if err != nil {
		return nil, err
	}
	file, prot, err := d.target(req)
	if err != nil {
		return nil, err
	}
	if err := prot.check(req.Kind, pattern); err != nil {
		return nil, err
	}
	if _, _, err := d.store.edit(file, addRule(req.Kind, pattern)); err != nil {
		return nil, err
	}
	sessions := d.sessionsFor(map[bool]string{true: "", false: file}[req.Scope == "global"])
	results := d.push(sessions, sydCommands(req.Kind, pattern, "+"))
	d.mu.Lock()
	for k, c := range d.cards {
		if (req.Scope == "global" || c.RulesFile == file) && covers(req.Kind, pattern, c) {
			d.resolveLocked(k, req.Kind != "ignore")
		}
	}
	d.mu.Unlock()
	return map[string]any{"saved": file, "sessions": results}, nil
}

func (d *Daemon) remove(req editReq) (any, error) {
	file, _, err := d.target(req)
	if err != nil {
		return nil, err
	}
	if _, _, err := d.store.edit(file, removeRule(req.Kind, req.Pattern)); err != nil {
		return nil, err
	}
	sessions := d.sessionsFor(map[bool]string{true: "", false: file}[req.Scope == "global"])
	var cmds []string
	if n, err := normalize(req.Kind, req.Pattern); err == nil {
		cmds = sydCommands(req.Kind, n, "-")
	}
	out := map[string]any{"saved": file, "sessions": d.push(sessions, cmds)}
	if note := d.stillAllowedBy(sessions, req.Kind, req.Pattern); note != "" {
		out["note"] = note
	}
	return out, nil
}

// stillAllowedBy explains when a removed path rule is still covered by another.
func (d *Daemon) stillAllowedBy(sessions []*Session, kind, pattern string) string {
	if kind != "read" && kind != "write" {
		return ""
	}
	probe := literalPrefix(expandHome(pattern))
	for _, s := range sessions {
		var pats []string
		for _, r := range []Rules{d.store.get(globalRulesPath()), d.store.get(s.RulesFile)} {
			pats = append(pats, r.Write...)
			if kind == "read" {
				pats = append(pats, r.Read...)
			}
		}
		for _, b := range baseline(s.Project) {
			if b.Kind == "write" || kind == "read" {
				pats = append(pats, b.Pattern)
			}
		}
		for _, p := range pats {
			if p != pattern && matchPath(p, probe) {
				return fmt.Sprintf("still allowed by %s", p)
			}
		}
	}
	return ""
}

// resolveAdded releases cards (and paused requests) covered by rules that
// were added between before and after. rulesFile "" = global.
func (d *Daemon) resolveAdded(before, after Rules, rulesFile string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, kind := range kinds {
		for _, p := range *after.list(kind) {
			if slices.Contains(*before.list(kind), p) {
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
		return ignored([]Rules{{Ignore: []string{pattern}}}, c.Kind, c.Target)
	case "hosts":
		if c.Kind != "hosts" {
			return false
		}
		h, err := parseHostRule(pattern)
		scheme, rest, _ := strings.Cut(c.Target, "://")
		host, port, _ := net.SplitHostPort(rest)
		return err == nil && h.match(scheme, host, port)
	case "connect":
		return c.Kind == "connect" && pattern == c.Target
	case "write":
		return (c.Kind == "write" || c.Kind == "read") && matchPath(pattern, c.Target)
	case "read":
		return c.Kind == "read" && matchPath(pattern, c.Target)
	}
	return false
}

// Events -> cards -----------------------------------------------------------

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

func (d *Daemon) events(sessionID string, lines []string) {
	d.mu.Lock()
	s, ok := d.sessions[sessionID]
	d.mu.Unlock()
	if !ok {
		return
	}
	rules := []Rules{d.store.get(globalRulesPath()), d.store.get(s.RulesFile)}
	prot := protectedFor(s.Project, s.RulesFile, globalRulesPath())
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, line := range lines {
		var e sydEvent
		if json.Unmarshal([]byte(line), &e) != nil || e.Ctx != "access" || (e.Act != "deny" && e.Act != "warn") {
			continue
		}
		caps := e.caps()
		kind, target := "", ""
		switch {
		case slices.Contains(caps, "net/connect") && e.Addr != "":
			kind, target = "connect", strings.TrimPrefix(strings.TrimPrefix(e.Addr, "tcp!"), "udp!")
		case slices.Contains(caps, "net/connect") && e.Unix != "" && !strings.HasPrefix(e.Unix, "@sydguard-") && !strings.HasPrefix(e.Unix, "@"):
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
		if safeText(target) != nil || (strings.HasPrefix(target, "/") && safePath(target) != nil) {
			continue // never turn unprintable names into rules
		}
		if (kind == "read" || kind == "write") && prot.check(kind, target) != nil {
			continue // protected paths are never grantable, so don't ask
		}
		if ignored(rules, kind, target) {
			continue
		}
		learned := e.Act == "warn"
		dir := e.Type == "dir"
		if learned && kind != "connect" {
			target, dir = learnRoot(target), true
		}
		d.addCardLocked(s, kind, target, e.Cmd, learned, dir, "")
	}
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
	c := &Card{ID: newID(), Session: s.ID, Project: s.Project, RulesFile: s.RulesFile, Kind: kind, Target: target,
		Cmd: truncate(cmd, 200), Count: 1, Last: time.Now(), Learned: learned, Note: note}
	switch kind {
	case "read", "write":
		c.Options = suggestions(target, dir)
		if !learned && !dir {
			c.Note = "denied — the agent will see an error; it succeeds on retry once applied"
		}
	case "hosts":
		scheme, rest, _ := strings.Cut(target, "://")
		host, port, _ := net.SplitHostPort(rest)
		c.Options = hostSuggestions(scheme, host, port)
	default:
		c.Options = []string{target}
		c.Note = "raw network target (the tool bypassed the proxy)"
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

// State ---------------------------------------------------------------------

type rulesView struct {
	ruleFile
	Project  string     `json:"project"`
	Baseline []baseRule `json:"baseline,omitempty"`
	Sessions []string   `json:"sessions"`
}

func (d *Daemon) state() map[string]any {
	d.mu.Lock()
	sessions := make([]Session, 0, len(d.sessions))
	files := map[string]string{} // rules file -> project
	for _, s := range d.sessions {
		sessions = append(sessions, *s)
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
	for _, f := range knownRulesFiles() {
		if _, ok := files[f]; !ok && f != globalRulesPath() {
			files[f] = projectOfRulesFile(f)
		}
	}
	views := []rulesView{}
	for f, p := range files {
		v := rulesView{ruleFile: d.store.view(f), Project: p, Sessions: []string{}}
		if p != "" {
			v.Baseline = baseline(p)
		}
		for _, s := range sessions {
			if s.RulesFile == f {
				v.Sessions = append(v.Sessions, s.ID)
			}
		}
		views = append(views, v)
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Path < views[j].Path })
	return map[string]any{"version": selfVersion(), "sessions": sessions, "cards": cards, "files": views,
		"global": d.store.view(globalRulesPath())}
}

// Client side ---------------------------------------------------------------

func unixClient(sock string, timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
}

func callAt(client *http.Client, method, path string, in, out any) error {
	var body strings.Reader
	if in != nil {
		data, _ := json.Marshal(in)
		body = *strings.NewReader(string(data))
	}
	req, err := http.NewRequest(method, "http://sydguard"+path, &body)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		var e struct{ Error string }
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("%s", e.Error)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func call(method, path string, in, out any) error {
	return callAt(unixClient(daemonSocket(), 15*time.Second), method, path, in, out)
}

// ensureDaemon starts the background daemon if needed (restarting it when the
// binary changed). Returns true when a new daemon was started.
func ensureDaemon() (bool, error) {
	var ping struct{ Version string }
	if err := call("GET", "/api/ping", nil, &ping); err == nil {
		if ping.Version == selfVersion() {
			return false, nil
		}
		_ = call("POST", "/internal/quit", nil, nil)
		time.Sleep(400 * time.Millisecond)
	}
	if err := os.MkdirAll(stateDir(), 0o700); err != nil {
		return false, err
	}
	if err := spawnDetached(filepath.Join(stateDir(), "daemon.log"), "daemon"); err != nil {
		return false, err
	}
	for range 50 {
		time.Sleep(100 * time.Millisecond)
		if call("GET", "/api/ping", nil, &ping) == nil && ping.Version == selfVersion() {
			return true, nil
		}
	}
	return false, errors.New("daemon did not start; see " + filepath.Join(stateDir(), "daemon.log"))
}
