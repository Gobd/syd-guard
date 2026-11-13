package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"embed"
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
	"time"
)

//go:embed ui.html
var uiFS embed.FS

const defaultUIPort = 7878

func uiPort() int {
	var p int
	if _, err := fmt.Sscan(os.Getenv("SYDGUARD_PORT"), &p); err == nil && p > 0 {
		return p
	}
	return defaultUIPort
}

func uiURL(token string) string { return fmt.Sprintf("http://127.0.0.1:%d/#%s", uiPort(), token) }

type Session struct {
	ID        string    `json:"id"`
	Project   string    `json:"project"`
	Cwd       string    `json:"cwd"`
	Cmd       []string  `json:"cmd"`
	Learn     bool      `json:"learn"`
	PID       int       `json:"pid"`
	IPC       string    `json:"ipc"`
	ProxyPort int       `json:"proxyPort"`
	Started   time.Time `json:"started"`
	Launch    []string  `json:"launch"` // read+exec paths for the launched binary
	proxy     *http.Server
}

type Card struct {
	ID      string    `json:"id"`
	Session string    `json:"session"`
	Project string    `json:"project"`
	Kind    string    `json:"kind"` // read, write, connect, hosts
	Target  string    `json:"target"`
	Cmd     string    `json:"cmd"`
	Count   int       `json:"count"`
	Last    time.Time `json:"last"`
	Learned bool      `json:"learned"`
	Waiting int       `json:"waiting"` // proxy connections blocked on this card
	Options []string  `json:"options"`
	waiters []chan bool
}

type Daemon struct {
	mu       sync.Mutex
	token    string
	sessions map[string]*Session
	cards    map[string]*Card // key: project|kind|target
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func readToken() (string, error) {
	b, err := os.ReadFile(filepath.Join(stateDir(), "token"))
	return strings.TrimSpace(string(b)), err
}

func runDaemon() error {
	if err := os.MkdirAll(filepath.Join(stateDir(), "sessions"), 0o700); err != nil {
		return err
	}
	_ = os.Chmod(stateDir(), 0o700)
	token, err := readToken()
	if err != nil || len(token) < 32 {
		b := make([]byte, 24)
		_, _ = rand.Read(b)
		token = hex.EncodeToString(b)
		if err := os.WriteFile(filepath.Join(stateDir(), "token"), []byte(token+"\n"), 0o600); err != nil {
			return err
		}
	}
	d := &Daemon{token: token, sessions: map[string]*Session{}, cards: map[string]*Card{}}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", uiPort()))
	if err != nil {
		return err
	}
	d.adoptSessions()
	go d.reap()
	log.Printf("sydguard daemon %s listening on %s", selfVersion(), ln.Addr())
	return http.Serve(ln, d.routes())
}

// adoptSessions re-attaches sessions that survived a daemon restart.
func (d *Daemon) adoptSessions() {
	files, _ := filepath.Glob(filepath.Join(stateDir(), "sessions", "*.json"))
	for _, f := range files {
		var s Session
		data, err := os.ReadFile(f)
		if err != nil || json.Unmarshal(data, &s) != nil || !alive(s.PID) {
			d.removeSessionFiles(s.ID, f)
			continue
		}
		if err := d.startProxy(&s); err != nil {
			log.Printf("adopt %s: %v", s.ID, err)
			continue
		}
		d.sessions[s.ID] = &s
		log.Printf("adopted session %s (%s)", s.ID, s.Project)
	}
}

func (d *Daemon) removeSessionFiles(id, f string) {
	_ = os.Remove(f)
	if id != "" {
		_ = os.Remove(filepath.Join(stateDir(), "sessions", id+".syd-3"))
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

func (d *Daemon) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		data, _ := uiFS.ReadFile("ui.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'")
		_, _ = w.Write(data)
	})
	api := func(pattern string, h func(r *http.Request) (any, error)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+d.token {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			out, err := h(r)
			w.Header().Set("Content-Type", "application/json")
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				out = map[string]string{"error": err.Error()}
			}
			_ = json.NewEncoder(w).Encode(out)
		})
	}
	api("GET /api/ping", func(*http.Request) (any, error) { return map[string]string{"version": selfVersion()}, nil })
	api("GET /api/state", func(*http.Request) (any, error) { return d.state() })
	api("POST /api/allow", func(r *http.Request) (any, error) {
		var req struct{ Card, Scope, Project, Kind, Pattern string }
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		return nil, d.allow(req.Card, req.Scope, req.Project, req.Kind, req.Pattern)
	})
	api("POST /api/dismiss", func(r *http.Request) (any, error) {
		var req struct{ Card string }
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
		return nil, nil
	})
	api("POST /api/remove", func(r *http.Request) (any, error) {
		var req struct{ Scope, Project, Kind, Pattern string }
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		return nil, d.remove(req.Scope, req.Project, req.Kind, req.Pattern)
	})
	api("POST /internal/session", func(r *http.Request) (any, error) {
		var s Session
		if err := decode(r, &s); err != nil {
			return nil, err
		}
		return d.register(&s)
	})
	api("POST /internal/events", func(r *http.Request) (any, error) {
		var req struct {
			Session string
			Lines   []string
		}
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		d.events(req.Session, req.Lines)
		return nil, nil
	})
	api("POST /internal/end", func(r *http.Request) (any, error) {
		var req struct{ Session string }
		if err := decode(r, &req); err != nil {
			return nil, err
		}
		d.mu.Lock()
		d.endLocked(req.Session)
		d.mu.Unlock()
		return nil, nil
	})
	api("POST /internal/quit", func(*http.Request) (any, error) {
		go func() { time.Sleep(100 * time.Millisecond); os.Exit(0) }()
		return nil, nil
	})
	// Reject DNS-rebinding: only literal loopback hosts.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.Host)
		if host != "127.0.0.1" && host != "localhost" {
			http.Error(w, "bad host", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func decode(r *http.Request, v any) error {
	return json.NewDecoder(http.MaxBytesReader(nil, r.Body, 4<<20)).Decode(v)
}

func (d *Daemon) register(s *Session) (any, error) {
	if !filepath.IsAbs(s.Project) || len(s.Cmd) == 0 {
		return nil, fmt.Errorf("bad session")
	}
	s.ID = newID()
	s.IPC = "@sydguard-" + s.ID + "-" + newID()
	s.Started = time.Now()
	global, err := loadRules("")
	if err != nil {
		return nil, err
	}
	project, data, err := loadRulesBytes(s.Project)
	if err != nil {
		return nil, err
	}
	if !trusted(s.Project, data) {
		return nil, fmt.Errorf("%s changed outside sydguard; run again from a terminal to review and trust it", profilePath(s.Project))
	}
	if err := d.startProxy(s); err != nil {
		return nil, err
	}
	dir := filepath.Join(stateDir(), "sessions")
	profile := filepath.Join(dir, s.ID+".syd-3")
	if err := os.WriteFile(profile, []byte(compileProfile(s.Project, append([]Rules{{Read: s.Launch}}, global, project), s.ProxyPort, s.IPC, s.Learn)), 0o600); err != nil {
		return nil, err
	}
	meta, _ := json.Marshal(s)
	if err := os.WriteFile(filepath.Join(dir, s.ID+".json"), meta, 0o600); err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.sessions[s.ID] = s
	d.mu.Unlock()
	log.Printf("session %s started: %s in %s", s.ID, strings.Join(s.Cmd, " "), s.Project)
	return map[string]any{"id": s.ID, "profile": profile, "proxyPort": s.ProxyPort}, nil
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
	saved := 0
	for k, c := range d.cards {
		if c.Session != id {
			continue
		}
		if c.Learned && s.Learn && len(c.Options) > 0 {
			// Learn runs save what they saw, so the next normal run just works.
			if err := d.editRules(s.Project, c.Kind, c.Options[0], true); err == nil {
				saved++
			} else {
				log.Printf("learn: %s %s: %v", c.Kind, c.Options[0], err)
				continue
			}
		}
		d.resolveLocked(k, false)
	}
	if saved > 0 {
		log.Printf("session %s: learned %d rules into %s", id, saved, profilePath(s.Project))
	}
	d.removeSessionFiles(id, filepath.Join(stateDir(), "sessions", id+".json"))
	log.Printf("session %s ended", id)
}

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

// events turns Syd access-violation log lines into approval cards.
func (d *Daemon) events(sessionID string, lines []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, ok := d.sessions[sessionID]
	if !ok {
		return
	}
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
		case slices.Contains(caps, "net/connect") && e.Unix != "" && !strings.HasPrefix(e.Unix, "@sydguard-"):
			kind, target = "connect", e.Unix
		case e.Path == "" || strings.HasPrefix(e.Path, "!") || strings.HasPrefix(e.Path, "/proc/self/fd/"):
			continue
		case slices.ContainsFunc(caps, func(c string) bool { return slices.Contains(writeLike, c) }):
			kind, target = "write", e.Path
		case slices.ContainsFunc(caps, func(c string) bool { return strings.HasPrefix(c, "read") || c == "exec" || c == "chdir" || c == "stat" }):
			kind, target = "read", e.Path
		default:
			continue
		}
		if checkProtected(s.Project, kind, target) != nil {
			continue // protected paths are never grantable, so don't ask
		}
		if rules := d.rulesFor(s.Project); ignored(rules, kind, target) {
			continue
		}
		learned := e.Act == "warn"
		if learned && kind != "connect" {
			target = learnRoot(target) // learn mode: one suggestion per tool/cache root
		}
		d.addCardLocked(s, kind, target, e.Cmd, learned, e.Type == "dir" || learned)
	}
}

func (d *Daemon) rulesFor(project string) []Rules {
	g, _ := loadRules("")
	p, _ := loadRules(project)
	return []Rules{g, p}
}

func (d *Daemon) addCardLocked(s *Session, kind, target, cmd string, learned, dir bool) *Card {
	key := s.Project + "|" + kind + "|" + target
	if c, ok := d.cards[key]; ok {
		c.Count++
		c.Last = time.Now()
		return c
	}
	if len(d.cards) > 2000 {
		return nil
	}
	c := &Card{ID: newID(), Session: s.ID, Project: s.Project, Kind: kind, Target: target, Cmd: truncate(cmd, 200), Count: 1, Last: time.Now(), Learned: learned}
	switch kind {
	case "read", "write":
		c.Options = suggestions(target, dir)
	case "hosts":
		h, _, _ := net.SplitHostPort(target)
		c.Options = append(hostSuggestions(h), target)
	default:
		c.Options = []string{target}
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

func (d *Daemon) allow(cardID, scope, project, kind, pattern string) error {
	pattern, err := normalize(kind, pattern)
	if err != nil {
		return err
	}
	d.mu.Lock()
	if cardID != "" && project == "" && scope == "project" {
		for _, c := range d.cards {
			if c.ID == cardID {
				project = c.Project
			}
		}
	}
	d.mu.Unlock()
	if scope == "global" {
		project = ""
	} else if !filepath.IsAbs(project) {
		return fmt.Errorf("project scope needs a project")
	}
	if err := d.editRules(project, kind, pattern, true); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pushLocked(project, kind, pattern, "+")
	// Resolve every card the new rule now covers.
	for k, c := range d.cards {
		if (project == "" || c.Project == project) && covers(kind, pattern, c) {
			d.resolveLocked(k, true)
		}
	}
	return nil
}

func covers(kind, pattern string, c *Card) bool {
	if c.Kind != kind && !(kind == "write" && c.Kind == "read") {
		return false
	}
	switch kind {
	case "hosts":
		h, p, _ := net.SplitHostPort(c.Target)
		return matchHost(pattern, h, p)
	case "connect":
		return pattern == c.Target
	}
	return matchPath(pattern, c.Target)
}

func (d *Daemon) remove(scope, project, kind, pattern string) error {
	if scope == "global" {
		project = ""
	}
	if err := d.editRules(project, kind, pattern, false); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pushLocked(project, kind, pattern, "-")
	return nil
}

var rulesMu sync.Mutex

func (d *Daemon) editRules(project, kind, pattern string, add bool) error {
	rulesMu.Lock()
	defer rulesMu.Unlock()
	r, err := loadRules(project)
	if err != nil {
		return err
	}
	l := r.list(kind)
	if l == nil {
		return fmt.Errorf("unknown kind %q", kind)
	}
	i := slices.Index(*l, pattern)
	switch {
	case add && i < 0:
		*l = append(*l, pattern)
		sort.Strings(*l)
	case !add && i >= 0:
		*l = slices.Delete(*l, i, i+1)
	case !add:
		return fmt.Errorf("rule not found")
	default:
		return nil
	}
	return saveRules(project, r)
}

// pushLocked applies a rule change to every live session it affects, in place.
func (d *Daemon) pushLocked(project, kind, pattern, op string) {
	for _, s := range d.sessions {
		if project != "" && s.Project != project {
			continue
		}
		// Protection denies are re-appended after every change so they stay last
		// (Syd: last matching rule wins).
		for _, cmd := range append(sydCommands(kind, pattern, op), protectionCommands(s.Project)...) {
			if err := sydIPC(s.IPC, cmd); err != nil {
				log.Printf("session %s: %s: %v", s.ID, cmd, err)
			}
		}
	}
}

func sydIPC(addr, command string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", addr)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte(command + "\n")); err != nil {
		return err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && line == "" {
		return err
	}
	var ack struct {
		Err int    `json:"err"`
		Msg string `json:"msg"`
	}
	if json.Unmarshal([]byte(line), &ack) != nil || ack.Err != 0 {
		return fmt.Errorf("syd rejected: %s", strings.TrimSpace(line))
	}
	return nil
}

type projectView struct {
	Path  string `json:"path"`
	File  string `json:"file"`
	Rules Rules  `json:"rules"`
	Error string `json:"error,omitempty"`
}

func (d *Daemon) state() (any, error) {
	global, err := loadRules("")
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	sessions := make([]*Session, 0, len(d.sessions))
	seen := map[string]bool{}
	for _, s := range d.sessions {
		sessions = append(sessions, s)
		seen[s.Project] = true
	}
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].Started.Before(sessions[j].Started) })
	cards := make([]*Card, 0, len(d.cards))
	for _, c := range d.cards {
		c.Waiting = len(c.waiters)
		cards = append(cards, c)
		seen[c.Project] = true
	}
	sort.Slice(cards, func(i, j int) bool { return cards[i].Last.After(cards[j].Last) })
	for _, p := range knownProjects() {
		seen[p] = true
	}
	projects := []projectView{}
	for p := range seen {
		r, err := loadRules(p)
		v := projectView{Path: p, File: profilePath(p), Rules: r}
		if err != nil {
			v.Error = err.Error()
		}
		projects = append(projects, v)
	}
	sort.Slice(projects, func(i, j int) bool { return projects[i].Path < projects[j].Path })
	return map[string]any{"sessions": sessions, "cards": cards, "global": global, "projects": projects, "version": selfVersion()}, nil
}

// client side ---------------------------------------------------------------

func call(method, path string, in, out any) error {
	token, err := readToken()
	if err != nil {
		return err
	}
	var body *strings.Reader
	if in != nil {
		data, _ := json.Marshal(in)
		body = strings.NewReader(string(data))
	} else {
		body = strings.NewReader("")
	}
	req, _ := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", uiPort(), path), body)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		var e struct{ Error string }
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("daemon: %s %s", resp.Status, e.Error)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
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
		time.Sleep(300 * time.Millisecond)
	}
	if err := os.MkdirAll(stateDir(), 0o700); err != nil {
		return false, err
	}
	logf, err := os.OpenFile(filepath.Join(stateDir(), "daemon.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return false, err
	}
	defer func() { _ = logf.Close() }()
	if err := spawnDetached(logf, "daemon"); err != nil {
		return false, err
	}
	for range 50 {
		time.Sleep(100 * time.Millisecond)
		if call("GET", "/api/ping", nil, &ping) == nil {
			return true, nil
		}
	}
	return false, errors.New("daemon did not start; see " + filepath.Join(stateDir(), "daemon.log"))
}
