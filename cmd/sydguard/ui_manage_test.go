//go:build linux || darwin

package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestManagedUISubprocessLifecycle(t *testing.T) {
	base := os.TempDir()
	if runtime.GOOS == "darwin" {
		base = "/private/tmp"
	}
	root, err := os.MkdirTemp(base, "sui-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(root) }()
	home := filepath.Join(root, "h")
	bin := filepath.Join(root, "b")
	for _, p := range []string{home, bin} {
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fake := filepath.Join(bin, "limactl")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nprintf '{\"data\":[{\"id\":\"live-session\",\"name\":\"agent\",\"state\":\"running\",\"project\":\"/work\"}]}'\n"), 0o700); err != nil { //nolint:gosec // executable test fixture in a private temporary directory
		t.Fatal(err)
	}
	exe := filepath.Join(bin, "sydguard")
	build := func(target, marker string) {
		t.Helper()
		source, err := os.ReadFile("main.go")
		if err != nil {
			t.Fatal(err)
		}
		source = []byte(strings.Replace(string(source), `const version = "0.0.0-spike"`, `const version = "`+marker+`"`, 1))
		modified := filepath.Join(root, "main-"+marker+".go")
		if err := os.WriteFile(modified, source, 0o600); err != nil { //nolint:gosec // paths and markers are test-owned
			t.Fatal(err)
		}
		original, _ := filepath.Abs("main.go")
		overlay, _ := json.Marshal(map[string]any{"Replace": map[string]string{original: modified}})
		overlayPath := filepath.Join(root, "overlay.json")
		if err := os.WriteFile(overlayPath, overlay, 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("go", "build", "-overlay", overlayPath, "-o", target, ".") //nolint:gosec // test-owned overlay and output
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build: %v: %s", err, output)
		}
	}
	build(exe, "test-one")
	workload := exec.Command("sleep", "120")
	if err := workload.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = workload.Process.Kill(); _ = workload.Wait() }()
	env := append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, ".config"), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	run := func(args ...string) (string, error) {
		args = append([]string{"ui", "--backend", "lima"}, args[1:]...)
		cmd := exec.Command(exe, args...) //nolint:gosec // test-owned executable and fixed test arguments
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	defer func() {
		if out, err := run("ui", "stop"); err != nil {
			t.Logf("cleanup: %v: %s", err, out)
		}
	}()
	// Corrupt old metadata is discovery only; a free lifetime lock permits recovery.
	configDir := filepath.Join(home, ".config")
	if runtime.GOOS == "darwin" {
		configDir = filepath.Join(home, "Library", "Application Support")
	}
	// The concurrent commands also prove that only one listening generation wins.
	var wg sync.WaitGroup
	outputs := make([]string, 6)
	errs := make([]error, 6)
	for i := range outputs {
		wg.Add(1)
		go func(i int) { defer wg.Done(); outputs[i], errs[i] = run("ui", "--detach") }(i)
	}
	wg.Wait()
	for i := range outputs {
		if errs[i] != nil {
			t.Fatalf("startup %d: %v: %s", i, errs[i], outputs[i])
		}
		if outputs[i] != outputs[0] {
			t.Fatalf("different startup results: %q / %q", outputs[0], outputs[i])
		}
	}
	parse := func(output string) (*url.URL, string) {
		t.Helper()
		line := strings.Split(output, "\n")[0]
		u, err := url.Parse(strings.TrimPrefix(line, "Approvals UI: "))
		if err != nil || u.Host == "" {
			t.Fatalf("bad URL %q: %v", output, err)
		}
		token := strings.TrimPrefix(u.Fragment, "token=")
		u.Fragment = ""
		return u, token
	}
	u, token := parse(outputs[0])
	get := func(u *url.URL, token, origin, host string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest("GET", u.String()+"api/sessions", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if host != "" {
			req.Host = host
		}
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if status, body := get(u, token, "", ""); status != 200 || !strings.Contains(body, "live-session") {
		t.Fatalf("session before restart: %d %s", status, body)
	}
	if status, _ := get(u, "", "", ""); status != 401 {
		t.Fatalf("missing auth: %d", status)
	}
	if status, _ := get(u, token, "https://evil.example", ""); status != 403 {
		t.Fatalf("origin: %d", status)
	}
	if status, _ := get(u, token, "", "evil.example"); status != 403 {
		t.Fatalf("host: %d", status)
	}
	entries, err := os.ReadDir(filepath.Join(configDir, "sydguard", "ui"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("identity dir: %v %v", entries, err)
	}
	identityDir := filepath.Join(configDir, "sydguard", "ui", entries[0].Name())
	defer func() { _, _ = run("ui", "--vm", "other", "stop") }()
	other, err := run("ui", "--vm", "other", "--detach")
	if err != nil {
		t.Fatalf("other backend startup: %v %s", err, other)
	}
	otherURL, otherToken := parse(other)
	if otherURL.Host == u.Host || otherToken == token {
		t.Fatal("backend identities shared a UI generation")
	}
	if output, err := run("ui", "--vm", "other", "stop"); err != nil {
		t.Fatalf("stop other backend: %v %s", err, output)
	}
	if status, _ := get(u, token, "", ""); status != 200 {
		t.Fatalf("other backend stop interrupted first: %d", status)
	}
	metadataPath := filepath.Join(identityDir, "meta.json")
	original, err := os.ReadFile(metadataPath) //nolint:gosec // test-owned temporary metadata
	if err != nil {
		t.Fatal(err)
	}
	forged, _ := json.Marshal(uiMetadata{Identity: "lima:ai-sandbox", Nonce: strings.Repeat("b", 64)})
	if err := os.WriteFile(metadataPath, forged, 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := run("ui", "--detach"); err == nil {
		t.Fatalf("accepted forged handshake: %s", output)
	}
	if err := os.WriteFile(metadataPath, original, 0o600); err != nil { //nolint:gosec // test-owned temporary metadata
		t.Fatal(err)
	}
	if status, body := get(u, token, "", ""); status != 200 || !strings.Contains(body, "live-session") {
		t.Fatalf("forgery interrupted bridge: %d %s", status, body)
	}
	newExe := filepath.Join(bin, "next")
	build(newExe, "test-two")
	if err := os.Rename(newExe, exe); err != nil {
		t.Fatal(err)
	}
	output, err := run("ui", "restart")
	if err != nil {
		t.Fatalf("restart: %v: %s", err, output)
	}
	u2, token2 := parse(output)
	if token == token2 {
		t.Fatal("restart did not rotate token")
	}
	if status, _ := get(u2, token, "", ""); status != 401 {
		t.Fatalf("old token accepted: %d", status)
	}
	if status, body := get(u2, token2, "", ""); status != 200 || !strings.Contains(body, "live-session") {
		t.Fatalf("session after restart: %d %s", status, body)
	}
	status, err := run("ui", "status")
	if err != nil || !strings.Contains(status, "test-two") {
		t.Fatalf("restart did not use installed binary: %v %s", err, status)
	}
	if _, err := run("ui", "stop"); err != nil {
		t.Fatal(err)
	}
	if err := workload.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("UI restart/stop interrupted test-owned workload: %v", err)
	}
	// Stale metadata and a stale socket must not resurrect or signal any PID.
	meta, _ := json.Marshal(uiMetadata{Identity: "lima:ai-sandbox", Nonce: strings.Repeat("a", 64)})
	if err := os.WriteFile(filepath.Join(identityDir, "meta.json"), meta, 0o600); err != nil {
		t.Fatal(err)
	}
	stale, err := net.Listen("unix", filepath.Join(identityDir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = stale.Close()
	output, err = run("ui", "--detach")
	if err != nil {
		t.Fatalf("stale recovery: %v %s", err, output)
	}
	_, fresh := parse(output)
	if fresh == token2 {
		t.Fatal("stale recovery reused token")
	}
	if output, err := run("ui", "stop"); err != nil {
		t.Fatalf("stop: %v %s", err, output)
	}
	foreground := exec.Command(exe, "ui", "--backend", "lima") //nolint:gosec // test-owned executable and fixed arguments
	foreground.Env = env
	if err := foreground.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if foreground.ProcessState == nil {
			_ = foreground.Process.Kill()
			_ = foreground.Wait()
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		output, err = run("ui", "status")
		if err == nil && strings.Contains(output, "Approvals UI:") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("foreground did not start: %v %s", err, output)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if output, err := run("ui", "--detach"); err != nil || !strings.Contains(output, "Approvals UI:") {
		t.Fatalf("foreground reuse: %v %s", err, output)
	}
	if output, err := run("ui", "stop"); err != nil {
		t.Fatalf("stop foreground: %v %s", err, output)
	}
	if err := foreground.Wait(); err != nil {
		t.Fatalf("foreground exit: %v", err)
	}
	if err := workload.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("foreground shutdown interrupted workload: %v", err)
	}
}

func TestUITokenExpiry(t *testing.T) {
	var token uiToken
	first, err := token.current()
	if err != nil {
		t.Fatal(err)
	}
	if !token.authorize(first) {
		t.Fatal("fresh token rejected")
	}
	token.mu.Lock()
	token.expires = time.Now().Add(-time.Second)
	token.mu.Unlock()
	if token.authorize(first) {
		t.Fatal("expired token accepted")
	}
	second, err := token.current()
	if err != nil || first == second {
		t.Fatalf("token rotation: %v", err)
	}
}
