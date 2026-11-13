// Package ui is the approvals UI server. On a Mac it runs locally and reaches
// every running Lima VM's daemon over SSH-forwarded Unix sockets.
package ui

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Gobd/syd-guard/internal/api"
	"github.com/Gobd/syd-guard/internal/policy"
	"github.com/Gobd/syd-guard/internal/system"
)

//go:embed dist
var dist embed.FS

// The UI server runs on your Mac (or on the Linux machine when there's no Mac).
// It is the only TCP listener, needs a token, and talks to each VM's daemon
// over that VM's Unix socket (forwarded over Lima's SSH). On the Mac it also
// owns the global ("all projects") rules and mirrors them to every VM.

func uiPort() int {
	var p int
	if _, err := fmt.Sscan(os.Getenv("SYDGUARD_PORT"), &p); err == nil && p > 0 {
		return p
	}
	return 7878
}

func uiTokenPath() string { return filepath.Join(system.StateDir(), "ui-token") }

// Token is the secret the browser needs (kept in the state dir).
func Token() (string, error) {
	if b, err := os.ReadFile(uiTokenPath()); err == nil && len(strings.TrimSpace(string(b))) >= 32 {
		return strings.TrimSpace(string(b)), nil
	}
	if err := os.MkdirAll(system.StateDir(), 0o700); err != nil {
		return "", err
	}
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	t := hex.EncodeToString(b)
	return t, os.WriteFile(uiTokenPath(), []byte(t+"\n"), 0o600)
}

// URL is the UI address including the token.
func URL(token string) string { return fmt.Sprintf("http://127.0.0.1:%d/#%s", uiPort(), token) }

type backend struct {
	name    string
	sock    string // local Unix socket reaching that VM's daemon
	client  *http.Client
	fwding  bool // an ssh forward is starting or running
	ok      bool
	err     string
	synced  bool // global rules pushed since (re)connect
	watch   bool // an event watcher is running
	guestOK bool
}

type uiServer struct {
	mu       sync.Mutex
	token    string
	backends map[string]*backend
	store    *policy.Store // global rules (Mac only)
	ownsGlob bool
	events   *api.Broadcaster
}

// RunServer serves the UI until killed.
func RunServer() error {
	token, err := Token()
	if err != nil {
		return err
	}
	u := &uiServer{token: token, backends: map[string]*backend{}, store: policy.NewStore(), ownsGlob: system.IsMac(), events: api.NewBroadcaster()}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", uiPort()))
	if err != nil {
		return err
	}
	_ = os.WriteFile(filepath.Join(system.StateDir(), "ui.pid"), []byte(fmt.Sprint(os.Getpid())), 0o600)
	go u.discover()
	log.Printf("sydguard UI %s on %s", system.Version(), ln.Addr())
	return (&http.Server{Handler: u.routes(), ReadHeaderTimeout: 10 * time.Second}).Serve(ln)
}

// discover keeps one backend per running VM (Mac) or the local daemon (Linux).
func (u *uiServer) discover() {
	for {
		if system.IsMac() {
			u.discoverLima()
		} else {
			u.mu.Lock()
			if _, ok := u.backends["local"]; !ok {
				host, _ := os.Hostname()
				u.backends["local"] = &backend{name: host, sock: system.DaemonSocket(), client: api.UnixClient(system.DaemonSocket(), 15*time.Second), guestOK: true}
			}
			u.mu.Unlock()
		}
		u.mu.Lock()
		list := make([]*backend, 0, len(u.backends))
		for _, b := range u.backends {
			list = append(list, b)
		}
		u.mu.Unlock()
		for _, b := range list {
			u.check(b)
		}
		time.Sleep(3 * time.Second)
	}
}

type limaInstance struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Dir    string `json:"dir"`
}

func limaInstances() []limaInstance {
	out, err := exec.Command("limactl", "list", "--json").Output()
	if err != nil {
		return nil
	}
	var list []limaInstance
	for _, line := range strings.Split(string(out), "\n") {
		var li limaInstance
		if json.Unmarshal([]byte(line), &li) == nil && li.Name != "" {
			list = append(list, li)
		}
	}
	return list
}

func (u *uiServer) discoverLima() {
	running := map[string]limaInstance{}
	for _, li := range limaInstances() {
		if li.Status == "Running" {
			running[li.Name] = li
		}
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	for name := range u.backends {
		if _, ok := running[name]; !ok {
			delete(u.backends, name) // its ssh forward exits with the VM
		}
	}
	for name, li := range running {
		b, ok := u.backends[name]
		if !ok {
			sock := filepath.Join(system.StateDir(), "fwd", name+".sock")
			b = &backend{name: name, sock: sock, client: api.UnixClient(sock, 15*time.Second)}
			u.backends[name] = b
		}
		if !b.fwding {
			b.fwding = true
			go u.forward(b, li)
		}
	}
}

// forward starts the guest daemon if sydguard is installed there and forwards
// its Unix socket to a private local socket over Lima's SSH.
func (u *uiServer) forward(b *backend, li limaInstance) {
	fail := func(msg string) {
		time.Sleep(5 * time.Second) // don't hammer a VM that isn't ready
		u.mu.Lock()
		b.fwding, b.ok, b.err = false, false, msg
		u.mu.Unlock()
	}
	out, err := exec.Command("limactl", "shell", li.Name, "sh", "-c", `test -x ~/.local/bin/sydguard && ~/.local/bin/sydguard daemon-ensure >/dev/null && echo "$HOME"`).Output()
	if err != nil {
		u.mu.Lock()
		b.guestOK = false
		u.mu.Unlock()
		fail("sydguard is not installed in this VM yet (run sydguard -- <cmd> once)")
		return
	}
	guestHome := strings.TrimSpace(string(out))
	if system.SafePath(guestHome) != nil {
		fail("bad guest home")
		return
	}
	_ = os.MkdirAll(filepath.Dir(b.sock), 0o700)
	_ = os.Remove(b.sock)
	cmd := exec.Command("ssh", "-F", filepath.Join(li.Dir, "ssh.config"), "-o", "ControlMaster=no", "-o", "ControlPath=none",
		"-o", "ExitOnForwardFailure=yes", "-o", "StreamLocalBindUnlink=yes", "-o", "ServerAliveInterval=15", "-o", "BatchMode=yes",
		"-N", "-L", b.sock+":"+guestHome+"/.local/state/sydguard/daemon.sock", "lima-"+li.Name)
	u.mu.Lock()
	b.guestOK, b.synced = true, false
	u.mu.Unlock()
	err = cmd.Run() // blocks while the forward is up
	fail(fmt.Sprintf("forward to %s ended: %v", li.Name, err))
}

func (u *uiServer) check(b *backend) {
	var ping struct{ Version string }
	err := api.Call(b.client, "GET", "/api/ping", nil, &ping)
	u.mu.Lock()
	b.ok = err == nil
	if err != nil && b.guestOK {
		b.err = "connecting…"
	} else if err == nil {
		b.err = ""
	}
	needSync := b.ok && !b.synced && u.ownsGlob
	startWatch := b.ok && !b.watch
	if startWatch {
		b.watch = true
	}
	u.mu.Unlock()
	if startWatch {
		go func() {
			// Relay the VM's change events to browsers (instant cards).
			stream := api.UnixClient(b.sock, 0)
			_ = api.WatchEvents(context.Background(), stream, "/api/events", u.events.Notify)
			u.mu.Lock()
			b.watch = false
			u.mu.Unlock()
		}()
	}
	if needSync {
		if err := u.syncGlobal(b); err == nil {
			u.mu.Lock()
			b.synced = true
			u.mu.Unlock()
		}
	}
}

// syncGlobal mirrors the Mac's global rules into a VM. If the Mac has none
// yet, it adopts the first VM's.
func (u *uiServer) syncGlobal(b *backend) error {
	if _, err := os.Stat(system.GlobalRulesPath()); errors.Is(err, os.ErrNotExist) {
		var st struct{ Global policy.RuleFile }
		if err := api.Call(b.client, "GET", "/api/state", nil, &st); err == nil {
			if _, _, err := u.store.Replace(system.GlobalRulesPath(), st.Global.Rules); err != nil {
				return err
			}
		}
	}
	return api.Call(b.client, "POST", "/api/global", map[string]any{"Rules": u.store.Get(system.GlobalRulesPath())}, nil)
}

func (u *uiServer) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		data, _ := dist.ReadFile("dist/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'")
		_, _ = w.Write(data)
	})
	handle := func(pattern string, h api.Func) {
		api.Handle(mux, pattern, func(r *http.Request) (any, error) {
			if r.Header.Get("Authorization") != "Bearer "+u.token {
				return nil, api.ErrUnauthorized
			}
			return h(r)
		})
	}
	mux.HandleFunc("GET /api/events", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != u.token { // EventSource can't send headers
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		u.events.Serve(w, r)
	})
	mux.Handle("GET /assets/", http.FileServerFS(sub(dist, "dist")))
	handle("GET /api/ping", func(*http.Request) (any, error) { return map[string]string{"version": system.Version()}, nil })
	handle("GET /api/state", func(*http.Request) (any, error) { return u.state(), nil })
	for _, op := range []string{"allow", "remove", "dismiss", "trust"} {
		handle("POST /api/"+op, func(r *http.Request) (any, error) {
			var req api.EditReq
			if err := api.Decode(r, &req); err != nil {
				return nil, err
			}
			if req.Scope == "global" && u.ownsGlob && op != "dismiss" {
				return u.editGlobal(op, req)
			}
			b := u.backend(req.VM)
			if b == nil {
				return nil, fmt.Errorf("VM %q isn't connected", req.VM)
			}
			var out map[string]any
			return out, api.Call(b.client, "POST", "/api/"+op, req, &out)
		})
	}
	// Reject DNS rebinding: only literal loopback hosts.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.Host)
		if host != "127.0.0.1" && host != "localhost" {
			http.Error(w, "bad host", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (u *uiServer) backend(name string) *backend {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, b := range u.backends {
		if b.name == name && b.ok {
			return b
		}
	}
	return nil
}

// editGlobal changes the Mac's global rules, then mirrors them to every VM
// (each VM applies the difference live) and reports per-VM results.
func (u *uiServer) editGlobal(op string, req api.EditReq) (any, error) {
	var fn func(*policy.Rules) error
	switch op {
	case "allow":
		pattern, err := policy.Normalize(req.Kind, req.Pattern)
		if err != nil {
			return nil, err
		}
		if err := policy.ProtectedFor("").Check(req.Kind, pattern); err != nil {
			return nil, err
		}
		fn = policy.AddRule(req.Kind, pattern)
	case "remove":
		fn = policy.RemoveRule(req.Kind, req.Pattern)
	case "trust":
		if _, _, err := u.store.TrustCurrent(system.GlobalRulesPath()); err != nil {
			return nil, err
		}
		fn = func(*policy.Rules) error { return nil }
	}
	if op != "trust" {
		if _, _, err := u.store.Edit(system.GlobalRulesPath(), fn); err != nil {
			return nil, err
		}
	}
	results := map[string]any{}
	u.mu.Lock()
	list := []*backend{}
	for _, b := range u.backends {
		if b.ok {
			list = append(list, b)
		}
	}
	u.mu.Unlock()
	for _, b := range list {
		var out map[string]any
		if err := api.Call(b.client, "POST", "/api/global", map[string]any{"Rules": u.store.Get(system.GlobalRulesPath())}, &out); err != nil {
			results[b.name] = map[string]string{"error": err.Error()}
			continue
		}
		results[b.name] = out // each VM releases cards the new rules cover
	}
	return map[string]any{"saved": system.GlobalRulesPath(), "vms": results}, nil
}

func (u *uiServer) state() map[string]any {
	u.mu.Lock()
	list := make([]*backend, 0, len(u.backends))
	for _, b := range u.backends {
		list = append(list, b)
	}
	u.mu.Unlock()
	sort.Slice(list, func(i, j int) bool { return list[i].name < list[j].name })
	vms := []map[string]any{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, b := range list {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v := map[string]any{"name": b.name, "ok": b.ok, "error": b.err}
			if b.ok {
				var st map[string]any
				if err := api.Call(b.client, "GET", "/api/state", nil, &st); err == nil {
					v["state"] = st
				} else {
					v["ok"], v["error"] = false, err.Error()
				}
			}
			mu.Lock()
			vms = append(vms, v)
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.Slice(vms, func(i, j int) bool { return vms[i]["name"].(string) < vms[j]["name"].(string) })
	out := map[string]any{"version": system.Version(), "vms": vms, "ownsGlobal": u.ownsGlob}
	if u.ownsGlob {
		out["global"] = u.store.View(system.GlobalRulesPath())
	}
	return out
}

// ensureUIServer starts the UI server in the background if needed. Returns
// true when it was (re)started.
// EnsureServer starts the UI server in the background if needed.
func EnsureServer() (bool, error) {
	token, err := Token()
	if err != nil {
		return false, err
	}
	ping := func() string {
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/api/ping", uiPort()), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
		if err != nil {
			return ""
		}
		defer func() { _ = resp.Body.Close() }()
		var p struct{ Version string }
		_ = json.NewDecoder(resp.Body).Decode(&p)
		if p.Version == "" {
			return "?"
		}
		return p.Version
	}
	switch v := ping(); v {
	case system.Version():
		return false, nil
	case "":
	default:
		if v == "?" {
			return false, fmt.Errorf("port %d is used by something else (set SYDGUARD_PORT)", uiPort())
		}
		_ = killUIServer()
	}
	if err := system.SpawnDetached(filepath.Join(system.StateDir(), "ui.log"), "ui-server"); err != nil {
		return false, err
	}
	for range 50 {
		time.Sleep(100 * time.Millisecond)
		if ping() == system.Version() {
			return true, nil
		}
	}
	return false, errors.New("UI server did not start; see " + filepath.Join(system.StateDir(), "ui.log"))
}

// killUIServer stops an older UI server (recorded by pid file).
func killUIServer() error {
	b, err := os.ReadFile(filepath.Join(system.StateDir(), "ui.pid"))
	if err != nil {
		return err
	}
	var pid int
	if _, err := fmt.Sscan(string(b), &pid); err != nil || pid <= 0 {
		return errors.New("bad pid")
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	_ = p.Kill()
	time.Sleep(300 * time.Millisecond)
	return nil
}

// OpenBrowser opens url on this machine.
func OpenBrowser(url string) {
	if system.IsMac() {
		_ = exec.Command("open", url).Run()
	} else if p, err := exec.LookPath("xdg-open"); err == nil {
		_ = exec.Command(p, url).Start()
	}
}

func sub(f embed.FS, dir string) fs.FS { s, _ := fs.Sub(f, dir); return s }
