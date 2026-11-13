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

// findEngine locates a working upstream Syd binary.
func findEngine() (string, error) {
	candidates := []string{os.Getenv("SYDGUARD_SYD"), "/usr/local/libexec/sydguard-syd-3.59.0", "/usr/local/bin/syd", "/usr/bin/syd"}
	if p, err := exec.LookPath("syd"); err == nil {
		candidates = append(candidates, p)
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if fi, err := os.Stat(c); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return c, nil
		}
	}
	return "", errors.New("syd not found: install upstream syd or set SYDGUARD_SYD")
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

// confirmTrust asks on the terminal before using a project rules file that
// sydguard didn't write itself (hand edit, git pull, freshly cloned repo).
func confirmTrust(project string) error {
	_, data, err := loadRulesBytes(project)
	if err != nil {
		return err
	}
	if trusted(project, data) {
		return nil
	}
	fmt.Fprintf(os.Stderr, "\nsydguard: %s was changed outside sydguard:\n\n%s\n", profilePath(project), data)
	fmt.Fprint(os.Stderr, "Trust these rules for this project? [y/N] ")
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return errors.New("rules file not trusted and no terminal to ask")
	}
	defer func() { _ = tty.Close() }()
	answer, _ := bufio.NewReader(tty).ReadString('\n')
	if !strings.EqualFold(strings.TrimSpace(answer), "y") {
		return errors.New("not trusted")
	}
	return trust(project, data)
}

func cmdRun(args []string, learn bool) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: sydguard [--learn] -- command [args...]")
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
	if err := confirmTrust(project); err != nil {
		return fail(err)
	}
	if _, err := ensureDaemon(); err != nil {
		return fail(err)
	}
	var reg struct {
		ID        string
		Profile   string
		ProxyPort int
	}
	if err := call("POST", "/internal/session", Session{Project: project, Cwd: cwd, Cmd: args, Learn: learn, PID: os.Getpid()}, &reg); err != nil {
		return fail(err)
	}
	mode := "enforcing " + profilePath(project)
	if learn {
		mode = "LEARNING (everything allowed and recorded)"
	}
	fmt.Fprintf(os.Stderr, "sydguard: %s — approvals at http://127.0.0.1:%d\n", mode, uiPort())

	logR, logW, err := os.Pipe()
	if err != nil {
		return fail(err)
	}
	cmd := exec.Command(engine, "-P", reg.Profile, "--")
	cmd.Args = append(cmd.Args, args...)
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
	if learn {
		fmt.Fprintf(os.Stderr, "sydguard: learning done — review suggestions at http://127.0.0.1:%d\n", uiPort())
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

// forwardEvents batches Syd's JSON log lines to the daemon. If the daemon is
// gone, it is restarted (it re-adopts this session from disk).
func forwardEvents(id string, r io.Reader) {
	lines := make(chan string, 1024)
	go func() {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			if bytes.Contains(sc.Bytes(), []byte(`"ctx":"access"`)) {
				lines <- sc.Text()
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

func spawnDetached(logf *os.File, args ...string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
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
