package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const sydVersion = "3.59." // the upstream release sydguard is tested with

// findEngine locates a working, tested upstream Syd: right version, and it
// actually runs (some locally built binaries crash).
func findEngine() (string, error) {
	candidates := []string{os.Getenv("SYDGUARD_SYD"), filepath.Join(home(), ".local/opt/syd-3.59.0-static/bin/syd"),
		"/usr/local/libexec/sydguard-syd-3.59.0", "/usr/local/bin/syd", "/usr/bin/syd"}
	if p, err := exec.LookPath("syd"); err == nil {
		candidates = append(candidates, p)
	}
	var problems []string
	for _, c := range candidates {
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
		return "", fmt.Errorf("no working Syd %sx found:\n  %s", sydVersion, strings.Join(problems, "\n  "))
	}
	return "", fmt.Errorf("syd %sx not found: run scripts/install-syd.sh in the VM or set SYDGUARD_SYD", sydVersion)
}

func probeEngine(path string) error {
	out, err := exec.Command(path, "--version").Output()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(string(out), "syd "+sydVersion) {
		return fmt.Errorf("version %q, want %sx", strings.SplitN(string(out), "\n", 2)[0], sydVersion)
	}
	if err := exec.Command(path, "-poff", "--", "/bin/true").Run(); err != nil {
		return fmt.Errorf("doesn't run: %w", err)
	}
	return nil
}

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
	_, data, err := readRulesFile(file)
	if err != nil {
		return err
	}
	if trusted(file, data) {
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
	return trust(file, data)
}

func cmdRun(o opts) int {
	args := o.args
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: sydguard [--learn] [--rules NAME|FILE] -- command [args...]")
		return 2
	}
	engine, err := findEngine()
	if err != nil {
		return fail(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return fail(err)
	}
	cwd, _ = filepath.EvalSymlinks(cwd)
	project := projectRoot(cwd)
	if project == "/" || project == home() || project == filepath.Dir(home()) {
		return fail(fmt.Errorf("refusing to make %s writable; run from a project directory", project))
	}
	for _, p := range []string{cwd, project} {
		if err := safePath(p); err != nil {
			return fail(fmt.Errorf("unsupported directory name: %w", err))
		}
	}
	rulesFile, err := rulesFileFor(project, cwd, o.rules)
	if err != nil {
		return fail(err)
	}
	if err := confirmTrust(rulesFile); err != nil {
		return fail(err)
	}
	if _, err := ensureDaemon(); err != nil {
		return fail(err)
	}
	if !o.fromMac {
		if started, err := ensureUIServer(); err != nil {
			fmt.Fprintln(os.Stderr, "sydguard: UI:", err)
		} else if started {
			token, _ := uiToken()
			openBrowser(uiURL(token))
		}
	}
	argv := append([]string(nil), args...)
	if p, err := exec.LookPath(argv[0]); err == nil {
		argv[0], _ = filepath.Abs(p) // Syd's own PATH search trips over hidden dirs
	}
	var reg struct {
		ID        string
		Profile   string
		ProxyPort int
	}
	s := Session{Project: project, RulesFile: rulesFile, Cwd: cwd, Cmd: args, Learn: o.learn, PID: os.Getpid(), Launch: launchPaths(argv[0])}
	if err := call("POST", "/internal/session", s, &reg); err != nil {
		return fail(err)
	}
	mode := "enforcing " + rulesFile
	if o.learn {
		mode = "LEARNING into " + rulesFile + " (everything allowed; what it uses is saved at exit)"
	}
	fmt.Fprintf(os.Stderr, "sydguard: %s — approvals at http://127.0.0.1:%d\n", mode, uiPort())

	logR, logW, err := os.Pipe()
	if err != nil {
		return fail(err)
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
	// The terminal delivers ^C etc. to the agent directly; we just outlive it.
	signal.Ignore(syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTSTP)
	if err := cmd.Start(); err != nil {
		return fail(err)
	}
	_ = logW.Close()
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
	_ = call("POST", "/internal/end", map[string]string{"Session": reg.ID}, nil)
	if o.learn {
		fmt.Fprintf(os.Stderr, "sydguard: learned rules saved to %s — review them at http://127.0.0.1:%d\n", rulesFile, uiPort())
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	if err != nil {
		return fail(err)
	}
	return 0
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
		if d := filepath.Dir(real); d != home() && d != "/" {
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
		if call("POST", "/internal/events", req, nil) != nil {
			if _, err := ensureDaemon(); err == nil {
				_ = call("POST", "/internal/events", req, nil)
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

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "sydguard:", err)
	return 1
}

func alive(pid int) bool { return pid > 0 && syscall.Kill(pid, 0) == nil }

func spawnDetached(logPath string, args ...string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = logf.Close() }()
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		return err
	}
	defer func() { _ = devnull.Close() }()
	cmd := exec.Command(exe, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

var versionOnce = sync.OnceValue(func() string {
	exe, err := os.Executable()
	if err != nil {
		return "unknown"
	}
	return fileHash(exe)
})

func selfVersion() string { return versionOnce() }

func fileHash(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	_, _ = io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func cmdDoctor() int {
	ok := true
	if engine, err := findEngine(); err != nil {
		fmt.Println("✗ engine:", err)
		ok = false
	} else {
		fmt.Println("✓ engine:", engine)
	}
	if _, err := ensureDaemon(); err != nil {
		fmt.Println("✗ daemon:", err)
		ok = false
	} else {
		fmt.Println("✓ daemon:", daemonSocket())
	}
	if !ok {
		return 1
	}
	return 0
}
