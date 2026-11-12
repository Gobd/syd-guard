package syd

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestMutableControlBoundaryIntegration(t *testing.T) {
	engine := os.Getenv("SYDGUARD_TEST_SYD")
	if runtime.GOOS != "linux" || engine == "" {
		t.Skip("requires Linux and explicit upstream candidate")
	}
	if _, err := exec.LookPath("socat"); err != nil {
		t.Skip("adversarial Unix-socket fixture requires socat; not a wrapper runtime dependency")
	}
	work, temporary, authority, extra := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	//nolint:gosec // private directory requires owner search permission
	if err := os.Chmod(authority, 0o700); err != nil {
		t.Fatal(err)
	}
	profile, err := Profile(work, temporary, []string{authority})
	if err != nil {
		t.Fatal(err)
	}
	profile += "allow/lock/read,readdir+" + extra + "\n"
	path := filepath.Join(authority, "mutable.syd-3")
	if err := os.WriteFile(path, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(authority, "syd.sock")
	if len(socket) >= 100 {
		t.Skip("test socket path exceeds conservative Unix limit")
	}
	file := filepath.Join(extra, "reference")
	if err := os.WriteFile(file, []byte("live-read"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	script := `set -eu
if cat "$1"; then echo INITIAL_READ_BYPASS; exit 80; fi
if printf 'version\n' | socat - "UNIX-CONNECT:$2"; then echo IPC_BYPASS; exit 81; fi
if stat '/dev/syd/allow/read+/***'; then echo VIRTUAL_API_BYPASS; exit 82; fi
printf ready > ready
while [ ! -f continue ]; do /bin/sleep 0.05; done
cat "$1" > result
if printf mutate > "$1"; then echo READ_ONLY_WRITE_BYPASS; exit 83; fi
printf MUTABLE_BOUNDARY_PASS
`
	command := exec.CommandContext(ctx, engine, "-P", path, "-m", "ipc:"+socket, "-m", "lock:ipc", "--", "/bin/sh", "-c", script, "fixture", file, socket) //nolint:gosec // fixed adversarial fixture, test-owned paths as argv; no shell interpolation
	command.Dir = work
	var output strings.Builder
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill() }()
	ready := filepath.Join(work, "ready")
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatalf("workload never reached denied-control gate:\n%s", output.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	client := IPC{Socket: socket}
	if _, err := client.Version(ctx); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal(err)
	}
	if err := client.GrantReadDirectory(ctx, extra); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "continue"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("live read-grant fixture failed: %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), "MUTABLE_BOUNDARY_PASS") {
		t.Fatalf("no completion sentinel:\n%s", output.String())
	}
	//nolint:gosec // test-owned output path
	result, err := os.ReadFile(filepath.Join(work, "result"))
	if err != nil || string(result) != "live-read" {
		t.Fatalf("live grant did not apply: %v %q", err, result)
	}
}
