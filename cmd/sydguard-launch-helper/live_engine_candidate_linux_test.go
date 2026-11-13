//go:build linux

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/syd"
)

const liveTransportCandidate = "/home/briankemper.guest/syd-abort-proof.lSrBGBxZ/bin/syd-3.59.0-abort"

// TestLiveEngineCandidateTransport is an ordinary-user, explicitly opted-in
// fixture. It exercises only the lower transport, not ROOT peer authentication.
func TestLiveEngineCandidateTransport(t *testing.T) {
	if os.Getenv("SYDGUARD_TEST_LIVE_ENGINE_CANDIDATE") != "1" {
		t.Skip("requires explicit ordinary candidate opt-in")
	}
	if os.Getuid() == 0 || os.Geteuid() == 0 || os.Getuid() != os.Geteuid() {
		t.Fatal("ordinary user required")
	}
	info, err := os.Lstat(liveTransportCandidate)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Uid != uint32(os.Getuid()) || info.Mode().Perm() != 0o700 {
		t.Fatal("untrusted candidate file")
	}
	data, err := os.ReadFile(liveTransportCandidate)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != liveEngineDigest {
		t.Fatal("candidate digest mismatch")
	}
	t.Logf("candidate=%s uid=%d mode=%04o sha256=%x", liveTransportCandidate, st.Uid, info.Mode().Perm(), digest)
	root, err := os.MkdirTemp("/home/briankemper.guest", "syd-transport-proof-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	for _, sub := range []string{"project", "scratch", "control"} {
		if err := os.Mkdir(filepath.Join(root, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	project, scratch, control := filepath.Join(root, "project"), filepath.Join(root, "scratch"), filepath.Join(root, "control")
	for path, value := range map[string]string{filepath.Join(project, "data"): "initial\n", filepath.Join(project, "dummy.env"): "private-dummy\n", filepath.Join(control, "private"): "private-dummy\n"} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	socket := filepath.Join(control, "s")
	binding := syd.BankBinding{Session: strings.Repeat("a", 64), Project: strings.Repeat("b", 64), Profile: "build", Generation: 1}
	ledger, startup, err := syd.NewBankLedger(binding, liveEngineDigest, project, scratch, socket, []string{control}, false)
	if err != nil {
		t.Fatal(err)
	}
	// Fixture-only preauthorized project RWD maximum; never used by production.
	ceiling := "allow/lock/read,readdir,write,create,delete,rename,truncate,mkdir,rmdir,symlink+" + project + "\n"
	startup = strings.Replace(startup, "domain+@sgbankA:@default\n", ceiling+"domain+@sgbankA:@default\n", 1)
	profile := filepath.Join(control, "startup.syd-3")
	if err := os.WriteFile(profile, []byte(startup), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, liveTransportCandidate, "-P", profile, "--", "/bin/sh", "-c", liveTransportShell, "fixture", project, control) //nolint:gosec // fixed candidate and test-owned fixture
	cmd.Dir = project
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Env = []string{"PATH=/usr/bin:/bin", "TMPDIR=" + scratch}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := os.Create(filepath.Join(control, "stderr.log"))
	if err != nil {
		t.Fatal(err)
	}
	stderrRead, stderrWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = stderrWrite
	if err := cmd.Start(); err != nil {
		_ = stderrRead.Close()
		_ = stderrWrite.Close()
		_ = stderr.Close()
		t.Fatal(err)
	}
	_ = stderrWrite.Close()
	stderrDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(stderr, stderrRead)
		_ = stderrRead.Close()
		_ = stderr.Close()
		close(stderrDone)
	}()
	waited := false
	pid := ""
	defer func() {
		_ = stdin.Close()
		if !waited {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			if p, e := strconv.Atoi(pid); e == nil && p > 1 {
				_ = syscall.Kill(p, syscall.SIGKILL)
			}
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		select {
		case <-stderrDone:
		case <-time.After(2 * time.Second):
			_ = stderrRead.Close()
			<-stderrDone
		}
		if t.Failed() {
			b, _ := os.ReadFile(filepath.Join(control, "stderr.log"))
			t.Logf("fixture stderr: %s", b)
		}
	}()
	t.Logf("fixture=%s engine_pid=%d socket=%s", root, cmd.Process.Pid, socket)
	for {
		if _, err := (syd.IPC{Socket: socket}).Version(ctx); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("candidate IPC readiness timeout")
		case <-time.After(20 * time.Millisecond):
		}
	}
	reader := bufio.NewReader(stdout)
	phase := func(name string) {
		t.Helper()
		if _, err := fmt.Fprintln(stdin, name); err != nil {
			t.Fatal(err)
		}
		lines := make(chan string, 1)
		fail := make(chan error, 1)
		go func() {
			line, e := reader.ReadString('\n')
			if e != nil {
				fail <- e
			} else {
				lines <- line
			}
		}()
		select {
		case line := <-lines:
			parts := strings.Fields(line)
			if len(parts) != 4 || parts[0] != "RESULT" || parts[1] != name || parts[3] != "OK" {
				t.Fatalf("invalid phase response %q", line)
			}
			if _, e := strconv.Atoi(parts[2]); e != nil {
				t.Fatal(e)
			}
			if pid == "" {
				pid = parts[2]
			} else if pid != parts[2] {
				t.Fatalf("shell PID changed: %s != %s", pid, parts[2])
			}
			t.Logf("phase=%s shell_pid=%s result=OK", name, pid)
		case err := <-fail:
			t.Fatal(err)
		case <-ctx.Done():
			t.Fatalf("phase timeout %s", name)
		}
	}
	phase("default")
	receipt := ledger.InitialReceipt()
	updates := []struct{ name, body, phase string }{
		{"full", `{"version":1,"name":"build","files":[{"path":".","access":["read","write","delete"],"recursive":true}],"network":[]}`, "full"},
		{"empty", `{"version":1,"name":"build","files":[],"network":[]}`, "empty"},
	}
	for _, update := range updates {
		batch, err := ledger.Prepare(receipt, []byte(update.body))
		if err != nil {
			t.Fatal(err)
		}
		conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
		if err != nil {
			_ = ledger.Finish(batch.Receipt, false)
			t.Fatal(err)
		}
		operation, stop := context.WithTimeout(ctx, 5*time.Second)
		err = sendLiveEngineBatch(operation, conn, batch.Bytes())
		stop()
		_ = conn.Close()
		if err != nil {
			_ = ledger.Finish(batch.Receipt, false)
			t.Fatalf("%s sealed-load ACK/EOF unknown; no retry: %v", update.name, err)
		}
		if err := ledger.Finish(batch.Receipt, true); err != nil {
			t.Fatal(err)
		}
		receipt = batch.Receipt
		t.Logf("sealed_load=%s sequence=%d bytes=%d revision=%s exact_ack_and_eof=true", update.name, receipt.Sequence, len(batch.Bytes()), receipt.Revision)
		phase(update.phase)
	}
	phase("exit")
	_ = stdin.Close()
	err = cmd.Wait()
	waited = true
	if err != nil {
		t.Fatalf("candidate exit: %v", err)
	}
	<-stderrDone
	logs, err := os.ReadFile(filepath.Join(control, "stderr.log"))
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string]int{filepath.Join(project, "data"): 0, filepath.Join(project, "dummy.env"): 0, filepath.Join(control, "private"): 0}
	scanner := bufio.NewScanner(strings.NewReader(string(logs)))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		var record struct {
			Action string `json:"act"`
			Path   string `json:"path"`
		}
		if json.Unmarshal(scanner.Bytes(), &record) == nil && record.Action == "deny" {
			if _, ok := checks[record.Path]; ok {
				checks[record.Path]++
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	for path, count := range checks {
		if count < 2 {
			t.Fatalf("missing candidate denial for %s: %d", path, count)
		}
		t.Logf("candidate_deny_path=%s count=%d", path, count)
	}
	sum := sha256.Sum256(logs)
	t.Logf("candidate_log_bytes=%d candidate_log_sha256=%x denial_records_present=true", len(logs), sum)
	t.Logf("PASS shell_pid=%s engine_pid=%d", pid, cmd.Process.Pid)
}

const liveTransportShell = `
project=$1
control=$2
fail() { printf 'FAIL phase=%s detail=%s pid=%s\n' "$phase" "$1" "$$" >&2; exit 90; }
protected() {
 if cat "$project/dummy.env" >&2 2>&2; then fail protected-dummy; fi
 if cat "$control/private" >&2 2>&2; then fail protected-control; fi
}
while IFS= read -r phase; do
 case "$phase" in
 default|empty) if cat "$project/data" >&2 2>&2; then fail denied-read; fi; if (printf bad > "$project/data") 2>&2; then fail denied-write; fi ;;
 full) cat "$project/data" >&2 2>&2 || fail allowed-read; printf changed > "$project/data" 2>&2 || fail allowed-write ;;
 exit) printf 'RESULT %s %s OK\n' "$phase" "$$"; exit 0 ;;
 *) fail unknown-phase ;;
 esac
 protected
 printf 'RESULT %s %s OK\n' "$phase" "$$"
done
exit 91
`
