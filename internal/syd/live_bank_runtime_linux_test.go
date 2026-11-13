//go:build linux

package syd

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

	"golang.org/x/sys/unix"
)

const bankRuntimeCandidate = "/home/briankemper.guest/syd-abort-proof.lSrBGBxZ/bin/syd-3.59.0-abort"

// This opt-in fixture uses an ordinary-owned candidate and a single private
// test operator. It does not authenticate a production engine or IPC peer.
func TestLiveBankGeneratedBatchCandidateIntegration(t *testing.T) {
	if os.Getenv("SYDGUARD_TEST_LIVE_BANK_ABORT") != "1" {
		t.Skip("requires explicit ordinary-user abort-candidate fixture opt-in")
	}
	if os.Getuid() == 0 || os.Geteuid() == 0 || os.Getuid() != os.Geteuid() {
		t.Fatal("fixture requires an ordinary user without elevated identity")
	}
	info, err := os.Lstat(bankRuntimeCandidate)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != uint32(os.Getuid()) || info.Mode().Perm() != 0700 {
		t.Fatal("candidate must be an ordinary-user-owned 0700 regular file")
	}
	candidate, err := os.ReadFile(bankRuntimeCandidate)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(candidate)
	if hex.EncodeToString(digest[:]) != liveBankEngineSHA256 {
		t.Fatal("candidate digest mismatch")
	}
	version, err := exec.Command(bankRuntimeCandidate, "--version").Output() //nolint:gosec // fixed candidate after identity checks
	if err != nil || !strings.HasPrefix(string(version), "syd 3.59.0 (Take It Back)\n") {
		t.Fatalf("candidate version: %q: %v", version, err)
	}
	t.Logf("candidate=%s uid=%d mode=%04o sha256=%x version=%q", bankRuntimeCandidate, stat.Uid, info.Mode().Perm(), digest, strings.SplitN(string(version), "\n", 2)[0])

	root, err := os.MkdirTemp("/home/briankemper.guest", "syd-bank-runtime-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	for _, sub := range []string{"project", "project/sub", "project/.ssh", "scratch", "control", "control/protected"} {
		if err := os.Mkdir(filepath.Join(root, sub), 0700); err != nil {
			t.Fatal(err)
		}
	}
	project, scratch, control := filepath.Join(root, "project"), filepath.Join(root, "scratch"), filepath.Join(root, "control")
	for path, data := range map[string]string{
		filepath.Join(project, "data"):             "initial\n",
		filepath.Join(project, "sub/nested"):       "nested\n",
		filepath.Join(project, "dummy.env"):        "dummy\n",
		filepath.Join(project, ".ssh/target"):      "protected\n",
		filepath.Join(control, "private"):          "private\n",
		filepath.Join(control, "protected/target"): "protected\n",
	} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("target", filepath.Join(control, "protected/link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(project, ".ssh/link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("data", filepath.Join(project, "normal-link")); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(control, "syd.sock")
	binding := BankBinding{Session: strings.Repeat("a", 64), Project: strings.Repeat("b", 64), Profile: "build", Generation: 1}
	ledger, startup, err := NewBankLedger(binding, liveBankEngineSHA256, project, scratch, socket, []string{control}, false)
	if err != nil {
		t.Fatal(err)
	}
	// Explicit fixture-only immutable ceiling: project read/write/delete maxima.
	// No mount changes; protected rules and lookup categories remain enabled.
	ceiling := "allow/lock/read,readdir,write,create,delete,rename,truncate,mkdir,rmdir,symlink+" + project + "\n"
	startup = strings.Replace(startup, "domain+@sgbankA:@default\n", ceiling+"domain+@sgbankA:@default\n", 1)
	profile := filepath.Join(control, "startup.syd-3")
	if err := os.WriteFile(profile, []byte(startup), 0600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, bankRuntimeCandidate, "-P", profile, "--", "/bin/sh", "-c", bankRuntimeShell, "fixture", project, control) //nolint:gosec // fixed candidate, profile, script and private fixture paths
	command.Dir = project
	// Keep this disposable session in its own process group for test cleanup.
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Env = []string{"PATH=/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE=1", "PYTHONNOUSERSITE=1", "TMPDIR=" + scratch}
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
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
	command.Stderr = stderrWrite
	if err := command.Start(); err != nil {
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
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			if shellPID, err := strconv.Atoi(pid); err == nil && shellPID > 1 {
				_ = syscall.Kill(shellPID, syscall.SIGKILL)
			}
			_ = command.Process.Kill()
			_ = command.Wait()
		}
		select {
		case <-stderrDone:
		case <-time.After(2 * time.Second):
			_ = stderrRead.Close()
			<-stderrDone
		}
		if t.Failed() {
			data, _ := os.ReadFile(filepath.Join(control, "stderr.log"))
			t.Logf("candidate stderr:\n%s", data)
		}
	}()
	t.Logf("fixture root=%s engine_pid=%d ceiling=fixture-project-only", root, command.Process.Pid)
	reader := bufio.NewReader(stdout)
	phase := func(name string) {
		t.Helper()
		if name != "exit" {
			if _, err := (IPC{Socket: socket}).Version(ctx); err != nil {
				t.Fatalf("private operator socket readiness before %s: %v", name, err)
			}
		}
		if _, err := fmt.Fprintln(stdin, name); err != nil {
			t.Fatal(err)
		}
		lineCh := make(chan string, 1)
		errCh := make(chan error, 1)
		go func() {
			line, err := reader.ReadString('\n')
			if err != nil {
				errCh <- err
				return
			}
			lineCh <- line
		}()
		select {
		case line := <-lineCh:
			parts := strings.Fields(line)
			if len(parts) != 4 || parts[0] != "RESULT" || parts[1] != name || parts[3] != "OK" {
				t.Fatalf("unexpected shell response: %q", line)
			}
			if _, err := strconv.Atoi(parts[2]); err != nil {
				t.Fatalf("invalid shell PID %q", parts[2])
			}
			if pid == "" {
				pid = parts[2]
			} else if pid != parts[2] {
				t.Fatalf("shell PID changed %s -> %s", pid, parts[2])
			}
			t.Logf("phase=%s shell_pid=%s result=OK", name, pid)
		case err := <-errCh:
			t.Fatalf("shell response %s: %v", name, err)
		case <-ctx.Done():
			t.Fatalf("shell phase %s timed out", name)
		}
	}
	// Wait for IPC without changing bank state.
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("IPC socket did not appear")
		case <-time.After(20 * time.Millisecond):
		}
	}
	phase("default")
	receipt := ledger.InitialReceipt()
	intents := []struct{ name, body, phase string }{
		{"full-A", `{"version":1,"name":"build","files":[{"path":".","access":["read","write","delete"],"recursive":true}],"network":[]}`, "full"},
		{"full-B", `{"version":1,"name":"build","files":[{"path":".","access":["read","write","delete"],"recursive":true}],"network":[]}`, "full"},
		{"exact-A", `{"version":1,"name":"build","files":[{"path":"data","access":["read"],"recursive":false}],"network":[]}`, "exact"},
		{"empty-B", `{"version":1,"name":"build","files":[],"network":[]}`, "empty"},
	}
	for _, update := range intents {
		batch, err := ledger.Prepare(receipt, []byte(update.body))
		if err != nil {
			t.Fatal(err)
		}
		ack, err := bankRuntimeLoad(socket, control, batch.Bytes())
		if err != nil {
			_ = ledger.Finish(batch.Receipt, false)
			t.Fatalf("%s uncertain load: %v", update.name, err)
		}
		t.Logf("load=%s bytes=%d sequence=%d revision=%s ACK err=%d msg=%q", update.name, len(batch.Bytes()), batch.Receipt.Sequence, batch.Receipt.Revision, ack.Err, ack.Message)
		if ack.Err != 0 || ack.Message != "ACK" {
			_ = ledger.Finish(batch.Receipt, false)
			t.Fatalf("%s rejected", update.name)
		}
		if err := ledger.Finish(batch.Receipt, true); err != nil {
			t.Fatal(err)
		}
		receipt = batch.Receipt
		phase(update.phase)
	}
	// The valid generated prefix selects default and mutates A. An additional
	// invalid addressed command forces a real parse failure before activation.
	failed, err := ledger.Prepare(receipt, []byte(intents[0].body))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(failed.Bytes()), "\n"), "\n")
	if len(lines) < 3 || lines[0] != "cmd/move!default" || lines[len(lines)-1] != "cmd/move!sgbankA" {
		t.Fatal("unexpected generated failure batch")
	}
	prefix := strings.Join(lines[:len(lines)-1], "\n") + "\n@missing/allow/read+" + filepath.Join(project, "data") + "\n"
	ack, err := bankRuntimeLoad(socket, control, []byte(prefix))
	if err != nil {
		_ = ledger.Finish(failed.Receipt, false)
		t.Fatalf("failure-prefix result unknown: %v", err)
	}
	t.Logf("load=failed-generated-prefix commands=%d bytes=%d ACK err=%d msg=%q", len(lines)-1, len(prefix), ack.Err, ack.Message)
	if ack.Err == 0 {
		_ = ledger.Finish(failed.Receipt, false)
		t.Fatal("invalid suffix unexpectedly acknowledged")
	}
	if err := ledger.Finish(failed.Receipt, false); err == nil {
		t.Fatal("negative result was accepted")
	}
	if _, err := ledger.Prepare(receipt, []byte(intents[0].body)); err == nil {
		t.Fatal("dirty ledger reused")
	}
	phase("default")
	// Lost ACK is modeled on a separate never-submitted ledger, not rollback.
	binding.Generation++
	model, _, err := NewBankLedger(binding, liveBankEngineSHA256, project, scratch, socket, []string{control}, false)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := model.Prepare(model.InitialReceipt(), []byte(intents[0].body))
	if err != nil {
		t.Fatal(err)
	}
	if model.Finish(unknown.Receipt, false) == nil {
		t.Fatal("modeled unknown accepted")
	}
	if _, err := model.Prepare(model.InitialReceipt(), []byte(intents[0].body)); err == nil {
		t.Fatal("modeled unknown reused")
	}
	t.Log("lost-ACK model=quarantined no-runtime-load no-rollback-claim")
	phase("exit")
	_ = stdin.Close()
	err = command.Wait()
	waited = true
	if err != nil {
		t.Fatalf("candidate exit: %v", err)
	}
	<-stderrDone
	logBytes, err := os.ReadFile(filepath.Join(control, "stderr.log"))
	if err != nil {
		t.Fatal(err)
	}
	bankRuntimeCheckDenials(t, logBytes, project, control, socket)
	logDigest := sha256.Sum256(logBytes)
	t.Logf("engine stderr bytes=%d sha256=%x", len(logBytes), logDigest)
	t.Logf("PASS shell_pid=%s engine_pid=%d", pid, command.Process.Pid)
}

type bankRuntimeACK struct {
	Err     int    `json:"err"`
	Message string `json:"msg"`
}

func bankRuntimeLoad(socket, control string, data []byte) (bankRuntimeACK, error) {
	var ack bankRuntimeACK
	file, err := os.CreateTemp(control, "batch-")
	if err != nil {
		return ack, err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(data); err != nil {
		_ = file.Close()
		return ack, err
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return ack, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return ack, fmt.Errorf("batch is not a regular file: %w", err)
	}
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return ack, err
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return ack, err
	}
	n, oobn, err := conn.WriteMsgUnix([]byte("load\n"), unix.UnixRights(int(file.Fd())), nil)
	if err != nil || n != 5 || oobn == 0 {
		return ack, fmt.Errorf("send one load FD: %d %d %v", n, oobn, err)
	}
	if err = json.NewDecoder(io.LimitReader(conn, 4096)).Decode(&ack); err != nil {
		return ack, err
	}
	return ack, nil
}

const bankRuntimeShell = `
project=$1
control=$2
fail() { printf 'FAIL phase=%s detail=%s pid=%s\n' "$phase" "$1" "$$" >&2; exit 90; }
protected() {
 if cat "$project/dummy.env" >&2 2>&2; then fail protected-env-read; fi
 if (printf bad > "$project/dummy.env") 2>&2; then fail protected-env-write; fi
 if cat "$control/private" >&2 2>&2; then fail protected-control-read; fi
 if (cd "$control/protected") 2>&2; then fail protected-control-chdir; fi
 if readlink "$control/protected/link" >&2 2>&2; then fail protected-control-readlink; fi
 if (cd "$project/.ssh") 2>&2; then fail protected-project-chdir; fi
 if readlink "$project/.ssh/link" >&2 2>&2; then fail protected-project-readlink; fi
 python3 -c 'import socket,sys
s=socket.socket(socket.AF_UNIX)
try:
 s.connect(sys.argv[1])
except (PermissionError, ConnectionRefusedError):
 sys.exit(0)
except OSError as e:
 print("unexpected connect error", e, file=sys.stderr)
 sys.exit(2)
sys.exit(1)' "$control/syd.sock" >&2 2>&2 || fail control-socket-not-denied
}
default_checks() {
 if cat "$project/data" >&2 2>&2; then fail default-read; fi
 if (printf bad > "$project/data") 2>&2; then fail default-write; fi
 if rm "$project/data" 2>&2; then fail default-delete; fi
 if mv "$project/data" "$project/moved" 2>&2; then fail default-rename; fi
}
while IFS= read -r phase; do
 case "$phase" in
 default|empty) default_checks ;;
 full)
   cat "$project/data" >&2 2>&2 || fail full-read
   printf edited > "$project/data" 2>&2 || fail full-write
   printf created > "$project/created" 2>&2 || fail full-create
   mv "$project/created" "$project/renamed" 2>&2 || fail full-rename
   rm "$project/renamed" 2>&2 || fail full-unlink
   cat "$project/sub/nested" >&2 2>&2 || fail full-recursive
   (cd "$project/sub") 2>&2 || fail full-chdir
   readlink "$project/normal-link" >&2 2>&2 || fail full-readlink
   ;;
 exact)
   cat "$project/data" >&2 2>&2 || fail exact-read
   if cat "$project/sub/nested" >&2 2>&2; then fail exact-recursive; fi
   if (printf bad > "$project/data") 2>&2; then fail exact-write; fi
   if rm "$project/data" 2>&2; then fail exact-delete; fi
   ;;
 exit) printf 'RESULT %s %s OK\n' "$phase" "$$"; exit 0 ;;
 *) fail unknown-phase ;;
 esac
 protected
 printf 'RESULT %s %s OK\n' "$phase" "$$"
done
exit 91
`

// Inspect the candidate's ordinary stderr records to distinguish an actual
// policy denial from an unrelated probe failure. This is not external tracing.
func bankRuntimeCheckDenials(t *testing.T, data []byte, project, control, socket string) {
	t.Helper()
	type denyRecord struct {
		Action string          `json:"act"`
		Cap    json.RawMessage `json:"cap"`
		Sys    string          `json:"sys"`
		Path   string          `json:"path"`
		Unix   string          `json:"unix"`
	}
	type expected struct {
		name, path, capability string
		count                  int
		sys                    string
	}
	checks := []expected{
		{name: "dummy-env-read", path: filepath.Join(project, "dummy.env"), capability: "read"},
		{name: "dummy-env-write", path: filepath.Join(project, "dummy.env"), capability: "write"},
		{name: "project-protected-chdir", path: filepath.Join(project, ".ssh"), capability: "chdir"},
		{name: "project-protected-readlink", path: filepath.Join(project, ".ssh/link"), capability: "readlink"},
		{name: "control-read", path: filepath.Join(control, "private"), capability: "read"},
		{name: "control-connect", path: socket, capability: "net/connect"},
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		var record denyRecord
		if json.Unmarshal(scanner.Bytes(), &record) != nil || record.Action != "deny" {
			continue
		}
		var caps []string
		var single string
		if json.Unmarshal(record.Cap, &single) == nil {
			caps = []string{single}
		} else {
			_ = json.Unmarshal(record.Cap, &caps)
		}
		for i := range checks {
			check := &checks[i]
			if record.Path != check.path && record.Unix != check.path {
				continue
			}
			for _, capability := range caps {
				if capability == check.capability {
					check.count++
					check.sys = record.Sys
					break
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	for _, check := range checks {
		if check.count < 6 {
			t.Fatalf("missing actual policy denial records: %s count=%d", check.name, check.count)
		}
		t.Logf("engine-denial=%s cap=%s syscall=%s count=%d path=%s", check.name, check.capability, check.sys, check.count, check.path)
	}
}
