//go:build linux

package learning

import (
	"bytes"
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Run only with an explicitly selected upstream static Syd; no root or daemon required.
func TestGuestSydPermissionCheckCandidate(t *testing.T) {
	engine := os.Getenv("SYDGUARD_TEST_SYD")
	if engine == "" {
		t.Skip("set SYDGUARD_TEST_SYD to an explicit static Syd 3.59.0")
	}
	if os.Geteuid() == 0 {
		t.Skip("fixture requires a non-root user for the DAC failure assertion")
	}
	binary, err := elf.Open(engine)
	if err != nil {
		t.Fatalf("static Syd must be an ELF executable: %v", err)
	}
	defer func() { _ = binary.Close() }()
	for _, program := range binary.Progs {
		if program.Type == elf.PT_INTERP {
			t.Fatal("Syd must be statically linked (ELF interpreter found)")
		}
	}
	libraries, err := binary.ImportedLibraries()
	if err != nil || len(libraries) != 0 {
		t.Fatalf("Syd must be statically linked: libraries=%v err=%v", libraries, err)
	}
	version, err := exec.Command(engine, "--version").Output() //nolint:gosec // explicit test-selected static ELF, fixed diagnostic argument
	if err != nil || !strings.HasPrefix(string(version), "syd 3.59.0 ") {
		t.Fatalf("requires Syd 3.59.0: %v", err)
	}
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil { //nolint:gosec // private test-owned profile parent required by Syd
		t.Fatal(err)
	}
	work := filepath.Join(base, "work")
	runtime := filepath.Join(base, "runtime")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(runtime, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"input": "SECRET_CONTENT_CANARY\n", "readonly": "readonly\n", ".env": "SECRET_ENV_CANARY\n"} {
		if err := os.WriteFile(filepath.Join(work, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(work, "readonly"), 0o444); err != nil { //nolint:gosec // intentionally read-only test sentinel for DAC failure
		t.Fatal(err)
	}
	workload := filepath.Join(work, "workload")
	script := `#!/bin/sh
set -eu
cd "$1"
cat input >/dev/null
printf data > created
mv created renamed
rm renamed
if (printf bad > readonly) 2>/dev/null; then exit 11; else echo DAC_FAILED; fi
if cat nonexistent >/dev/null 2>&1; then exit 12; else echo MISSING_FAILED; fi
if cat .env >/dev/null 2>&1; then exit 13; else echo PROTECTED_DENIED; fi
`
	if err := os.WriteFile(workload, []byte(script), 0o700); err != nil { //nolint:gosec // disposable executable fixture, no operator credentials
		t.Fatal(err)
	}
	profile := fmt.Sprintf(`include_profile fs
log/rlimit_interval:0
allow/create+!pipe
allow/stat+/proc/self/fd/pipe:*
allow/read,stat,readdir,readlink,chdir,exec+/usr/***
allow/read,stat,readdir,readlink,chdir,exec+/bin/***
allow/read,stat,readdir,readlink,chdir,exec+/lib/***
allow/read,stat,readdir,readlink,chdir,exec+/lib64/***
allow/lock/read,readdir,exec+/usr
allow/lock/read,readdir,exec+/bin
allow/lock/read,readdir,exec+/lib
allow/read,stat,readdir,readlink,chdir+/etc/***
allow/lock/read,readdir+/etc
allow/read,write,truncate,stat+/dev/null
allow/lock/read,write+/dev/null
allow/read,stat+/dev/urandom
allow/lock/read+/dev/urandom
allow/read,stat,readdir,readlink,chdir,write,create,delete,rename,truncate,chmod,chattr,mkdir,rmdir,symlink,exec+%s/***
allow/read,stat,readdir,readlink,chdir+%s
allow/lock/read,readdir,write,create,delete,rename,truncate,mkdir,rmdir,symlink,exec+%s
warn/read,write,create,delete,rename,truncate+%s/***
deny/all+/**/.env
deny/all+/**/.env/***
`, work, work, work, work)
	profilePath := filepath.Join(base, "profile.syd-3")
	if err := os.WriteFile(profilePath, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := New(Policy{Name: "guest", Temporary: runtime, PolicyDirectory: filepath.Join(work, ".sydguard"), RateLimitDisabled: true})
	if err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	cmd := exec.Command(engine, "-P", profilePath, "--", "/bin/sh", workload, work) //nolint:gosec // explicit tested engine, generated private profile and fixed fixture
	cmd.Dir = work
	cmd.Env = append(os.Environ(), "SYD_LOG=warn", "SYD_LOG_FD=3", "TMPDIR="+work)
	cmd.ExtraFiles = []*os.File{w}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		_ = w.Close()
		t.Fatal(err)
	}
	_ = w.Close()
	drained := make(chan error, 1)
	go func() { drained <- c.Drain(r) }()
	err = cmd.Wait()
	drainErr := <-drained
	outcome := Outcome{Err: err}
	if cmd.ProcessState != nil {
		outcome.ExitCode = cmd.ProcessState.ExitCode()
	}
	c.FinishOutcome(outcome)
	if err != nil || drainErr != nil {
		t.Fatalf("workload: %v; drain: %v; output: %s", err, drainErr, output.String())
	}
	for _, marker := range []string{"DAC_FAILED", "MISSING_FAILED", "PROTECTED_DENIED"} {
		if !strings.Contains(output.String(), marker) {
			t.Fatal("missing fixture assertion", marker)
		}
	}
	got := c.Snapshot()
	if got.Incomplete {
		t.Fatalf("unexpected incomplete: %+v", got)
	}
	has := func(name, access string) bool {
		for _, rule := range got.Profile.Files {
			if rule.Path == filepath.Join(work, name) {
				for _, a := range rule.Access {
					if a == access {
						return true
					}
				}
			}
		}
		return false
	}
	for _, pair := range [][2]string{{"input", "read"}, {"created", "write"}, {"created", "delete"}, {"renamed", "write"}, {"renamed", "delete"}, {"readonly", "write"}} {
		if !has(pair[0], pair[1]) {
			t.Errorf("missing permission check %v", pair)
		}
	}
	if has(".env", "read") || has("nonexistent", "read") {
		t.Fatal("unexpected denied/missing candidate")
	}
	// readonly write is present despite the workload's observed DAC failure. The
	// candidate is a permission check, never a claim of successful write.
}
