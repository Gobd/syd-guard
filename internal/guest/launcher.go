package guest

import (
	"bufio"
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/policy"
	"github.com/Gobd/syd-guard/internal/system"
)

const SydVersion = "3.59." // the upstream release sydguard is tested with

// EngineCandidates in preference order. Root-owned locations come first: they
// are the ones the AppArmor namespace exemption is installed for.
func EngineCandidates() []string {
	c := []string{
		os.Getenv("SYDGUARD_SYD"), "/usr/local/libexec/sydguard/syd", "/usr/local/libexec/sydguard-syd-3.59.0",
		filepath.Join(system.Home(), ".local/opt/syd-3.59.0-static/bin/syd"), "/usr/local/bin/syd", "/usr/bin/syd",
	}
	if p, err := exec.LookPath("syd"); err == nil {
		c = append(c, p)
	}
	return c
}

// FindEngine locates a working, tested upstream Syd: right version, and it
// actually runs (some locally built binaries crash).
var FindEngine = sync.OnceValues(func() (string, error) {
	var problems []string
	for _, c := range EngineCandidates() {
		if c == "" {
			continue
		}
		if fi, err := os.Stat(c); err != nil || !fi.Mode().IsRegular() || fi.Mode()&0o111 == 0 {
			continue
		}
		if err := probeEngine(c); err != nil {
			problems = append(problems, c+": "+err.Error())
			continue
		}
		return c, nil
	}
	if len(problems) > 0 {
		return "", fmt.Errorf("no working Syd %sx found:\n  %s", SydVersion, strings.Join(problems, "\n  "))
	}
	return "", fmt.Errorf("syd %sx not found: run `sydguard setup` (or scripts/install-syd.sh in the VM)", SydVersion)
})

func probeEngine(path string) error {
	out, err := exec.Command(path, "--version").Output()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(out), "syd "+SydVersion) {
		return fmt.Errorf("version %q, want %sx", strings.SplitN(string(out), "\n", 2)[0], SydVersion)
	}
	if err := exec.Command(path, "-poff", "--", "/bin/true").Run(); err != nil {
		return fmt.Errorf("doesn't run: %w", err)
	}
	return nil
}

// namespacesOK reports whether the engine may create user+mount namespaces
// (needed for the private DNS resolver and build-folder overlays). On Ubuntu
// this needs the AppArmor exemption installed by `sydguard setup`.
var namespacesOK = sync.OnceValue(func() bool {
	engine, err := FindEngine()
	if err != nil {
		return false
	}
	return exec.Command(engine, "-poff", "-m", "unshare/user:1", "-m", "unshare/mount:1", "--", "/bin/true").Run() == nil
})

// projectRoot is the git top level of dir, else dir itself.
func projectRoot(dir string) string {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--show-toplevel").Output()
	if err == nil {
		if p := strings.TrimSpace(string(out)); p != "" {
			return p
		}
	}
	return dir
}

// confirmTrust asks on the terminal before using a rules file sydguard didn't
// write itself (hand edit, git pull, freshly cloned repo).
func confirmTrust(file string) error {
	_, data, err := policy.ReadRulesFile(file)
	if err != nil {
		return err
	}
	if policy.Trusted(file, data) {
		return nil
	}
	fmt.Fprintf(os.Stderr, "\nsydguard: %s was changed outside sydguard:\n\n%s\n", file, data)
	fmt.Fprint(os.Stderr, "Trust these rules? [y/N] ")
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return errors.New("rules file not trusted and no terminal to ask")
	}
	defer func() { _ = tty.Close() }()
	answer, _ := bufio.NewReader(tty).ReadString('\n')
	if !strings.EqualFold(strings.TrimSpace(answer), "y") {
		return errors.New("not trusted")
	}
	return policy.Trust(file, data)
}

type RunOptions struct {
	Rules      string // --rules NAME|FILE
	Learn      bool
	LocalPorts []int // loopback ports of trusted helpers (e.g. an auth proxy)
	Args       []string
	// OnReady is called once the daemon is up, before the agent starts (the
	// CLI uses it to start the UI when not driven from the Mac).
	OnReady func()
}

// Run runs one agent under Syd and returns its exit code.
func Run(o RunOptions) (int, error) {
	if len(o.Args) == 0 {
		return 2, errors.New("usage: sydguard [--learn] [--rules NAME|FILE] -- command [args...]")
	}
	engine, err := FindEngine()
	if err != nil {
		return 1, err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return 1, err
	}
	cwd, _ = filepath.EvalSymlinks(cwd)
	project := projectRoot(cwd)
	if project == "/" || project == system.Home() || project == filepath.Dir(system.Home()) {
		return 1, fmt.Errorf("refusing to make %s writable; run from a project directory", project)
	}
	for _, p := range []string{cwd, project} {
		if err := system.SafePath(p); err != nil {
			return 1, fmt.Errorf("unsupported directory name: %w", err)
		}
	}
	rulesFile, err := policy.RulesFileFor(project, cwd, o.Rules)
	if err != nil {
		return 1, err
	}
	if err := confirmTrust(rulesFile); err != nil {
		return 1, err
	}
	cfg, err := config.Load()
	if err != nil {
		return 1, err
	}
	env, err := cfg.ResolvedEnv()
	if err != nil {
		return 1, err
	}
	localPorts := append(slices.Clone(o.LocalPorts), cfg.LocalPorts...)
	if _, err := EnsureDaemon(); err != nil {
		return 1, err
	}
	if o.OnReady != nil {
		o.OnReady()
	}
	argv := append([]string(nil), o.Args...)
	if p, err := exec.LookPath(argv[0]); err == nil {
		argv[0], _ = filepath.Abs(p) // Syd's own PATH search trips over hidden dirs
	}
	var reg struct {
		ID        string
		Profile   string
		ProxyPort int
		DNS       bool
		Overlays  []string
	}
	s := Session{
		Project: project, RulesFile: rulesFile, Cwd: cwd, Cmd: o.Args, Learn: o.Learn, PID: os.Getpid(),
		Launch: launchPaths(argv[0]), LocalPorts: localPorts, OverlayNames: cfg.OverlayNames(),
	}
	for k := range env {
		s.EnvNames = append(s.EnvNames, k)
	}
	if err := Call("POST", "/internal/session", s, &reg); err != nil {
		return 1, err
	}
	mode := "enforcing " + rulesFile
	if o.Learn {
		mode = "LEARNING into " + rulesFile + " (everything allowed; what it uses is saved at exit)"
	}
	fmt.Fprintf(os.Stderr, "sydguard: %s — approvals at http://127.0.0.1:7878\n", mode)
	if !reg.DNS {
		fmt.Fprintln(os.Stderr, "sydguard: note: no private DNS/overlays (namespaces unavailable; run `sydguard setup`)")
	} else if len(reg.Overlays) > 0 {
		fmt.Fprintf(os.Stderr, "sydguard: kept on the VM disk: %s\n", strings.Join(reg.Overlays, ", "))
	}

	logR, logW, err := os.Pipe()
	if err != nil {
		return 1, err
	}
	cmd := exec.Command(engine, "-P", reg.Profile, "--")
	cmd.Args = append(cmd.Args, argv...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{logW} // fd 3; Syd closes it before running the agent
	proxy := fmt.Sprintf("http://127.0.0.1:%d", reg.ProxyPort)
	cmd.Env = append(os.Environ(), "SYD_LOG_FD=3", "SYDGUARD=1", "NODE_USE_ENV_PROXY=1")
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "GLOBAL_AGENT_HTTP_PROXY"} {
		cmd.Env = append(cmd.Env, k+"="+proxy, strings.ToLower(k)+"="+proxy)
	}
	cmd.Env = append(cmd.Env, "NO_PROXY=localhost,127.0.0.1,::1", "no_proxy=localhost,127.0.0.1,::1")
	for k, v := range env { // secrets from the config, e.g. a scoped GH_TOKEN
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	// The terminal delivers ^C etc. to the agent directly; we just outlive it.
	signal.Ignore(syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTSTP)
	if err := cmd.Start(); err != nil {
		return 1, err
	}
	_ = logW.Close()
	_ = Call("POST", "/internal/started", map[string]any{"Session": reg.ID, "PID": cmd.Process.Pid}, nil)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for s := range sigs {
			_ = cmd.Process.Signal(s)
		}
	}()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); forwardEvents(reg.ID, logR) }()
	err = cmd.Wait()
	wg.Wait()
	_ = Call("POST", "/internal/end", map[string]string{"Session": reg.ID}, nil)
	if o.Learn {
		fmt.Fprintf(os.Stderr, "sydguard: learned rules saved to %s — review them at http://127.0.0.1:7878\n", rulesFile)
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), nil
	}
	if err != nil {
		return 1, err
	}
	return 0, nil
}

// launchPaths lets the sandbox run the command you asked for: the binary as
// found on PATH plus the directory its symlinks resolve to (read+exec only).
func launchPaths(path string) []string {
	if !filepath.IsAbs(path) {
		return nil
	}
	out := []string{path}
	if real, err := filepath.EvalSymlinks(path); err == nil && real != path {
		out = append(out, real)
		if d := filepath.Dir(real); d != system.Home() && d != "/" {
			out = append(out, d+"/***")
		}
	}
	if d := filepath.Dir(path); filepath.Base(d) == "bin" && d != "/usr/bin" && d != "/bin" {
		out = append(out, d+"/***") // sibling tools (pi -> node, etc.)
	}
	return out
}

// forwardEvents batches Syd's JSON log lines to the daemon. If the daemon is
// gone, it is restarted (it re-adopts this session from disk).
func forwardEvents(id string, r io.Reader) {
	lines := make(chan string, 1024)
	go func() {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		debug := os.Getenv("SYDGUARD_DEBUG") != ""
		for sc.Scan() {
			if debug {
				fmt.Fprintln(os.Stderr, "[syd]", sc.Text())
			}
			if bytes.Contains(sc.Bytes(), []byte(`"ctx":"access"`)) {
				select {
				case lines <- sc.Text():
				default: // daemon slow: drop rather than stall the agent
				}
			}
		}
		close(lines)
	}()
	var batch []string
	flush := func() {
		if len(batch) == 0 {
			return
		}
		req := map[string]any{"Session": id, "Lines": batch}
		if Call("POST", "/internal/events", req, nil) != nil {
			if _, err := EnsureDaemon(); err == nil {
				_ = Call("POST", "/internal/events", req, nil)
			}
		}
		batch = nil
	}
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case l, ok := <-lines:
			if !ok {
				flush()
				return
			}
			batch = append(batch, l)
			if len(batch) >= 200 {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

// Doctor prints what works and what doesn't. Returns false on a hard failure.
func Doctor() bool {
	ok := true
	if engine, err := FindEngine(); err != nil {
		fmt.Println("✗ engine:", err)
		ok = false
	} else {
		fmt.Println("✓ engine:", engine)
		if namespacesOK() {
			fmt.Println("✓ namespaces: private DNS and build-folder overlays available")
		} else {
			fmt.Println("! namespaces: unavailable (AppArmor?) — run `sydguard setup`; DNS rules and overlays are off")
		}
	}
	if _, err := EnsureDaemon(); err != nil {
		fmt.Println("✗ daemon:", err)
		ok = false
	} else {
		fmt.Println("✓ daemon:", system.DaemonSocket())
	}
	return ok
}

//go:embed install-syd.sh
var installScript string

// Setup installs the pinned Syd engine (and its AppArmor exemption).
func Setup() error {
	cmd := exec.Command("bash", "-c", installScript)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

// IPCLoad is the in-namespace helper: load one batch file into Syd's IPC.
func IPCLoad(ipc, batch string) error {
	if system.SafeText(ipc) != nil || system.SafePath(batch) != nil {
		return errors.New("bad arguments")
	}
	f, err := os.Open(batch)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return LoadFD(ipc, f)
}
