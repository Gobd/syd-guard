package syd

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/config"
)

// A path permission without a Landlock write ceiling must never write. Syd may
// reject this inconsistent profile at startup or deny the workload operation.
func TestStrictLandlockCeilingIntegration(t *testing.T) {
	engine := os.Getenv("SYDGUARD_TEST_SYD")
	if runtime.GOOS != "linux" || engine == "" {
		t.Skip("requires Linux and explicit static Syd 3.59.0")
	}
	if err := strictLandlockGate(); err != nil {
		t.Fatal(err)
	}
	work, temporary, authority := t.TempDir(), t.TempDir(), t.TempDir()
	target := filepath.Join(work, "file")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	profile, err := StrictProfile(work, temporary, []string{authority}, config.ResolvedProfile{})
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately allow Syd's path check, but not Landlock write.
	profile += "allow/write,truncate,create,chmod,chattr+" + target + "\n"
	profilePath := filepath.Join(authority, "profile")
	if err := os.WriteFile(profilePath, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, engine, "-P", profilePath, "--", "/bin/sh", "-c", `printf STARTED; if printf x > "$1"; then exit 91; fi`, "fixture", target) //nolint:gosec // fixed fixture and selected engine
	cmd.Dir = work
	cmd.Env = append(os.Environ(), "TMPDIR="+temporary)
	output, err := cmd.CombinedOutput()
	if err == nil && !bytes.Contains(output, []byte("STARTED")) {
		t.Fatalf("workload did not start: %s", output)
	}
	if err != nil && (bytes.Contains(output, []byte("STARTED")) || !bytes.Contains(output, []byte("EPERM"))) {
		t.Fatalf("unexpected profile failure: %v %s", err, output)
	}
	t.Logf("inconsistent profile: err=%v output=%q", err, output)
	if data, err := os.ReadFile(target); err != nil || string(data) != "original" { //nolint:gosec // test-owned sentinel; read verifies the kernel denial
		t.Fatalf("missing kernel ceiling: %q %v", data, err)
	}
}

func TestRunStrictAuthorizedInputsAndOwnedHandoffIntegration(t *testing.T) {
	engine := os.Getenv("SYDGUARD_TEST_SYD")
	if runtime.GOOS != "linux" || engine == "" {
		t.Skip("requires Linux and explicit static Syd 3.59.0")
	}
	// Syd TPE rejects execution beneath the shared /tmp ancestor. Use a
	// disposable directory under the unprivileged guest user's real home.
	realHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	external, err := os.MkdirTemp(realHome, ".sydguard-input-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(external) })
	home, work := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	for path, value := range map[string]string{filepath.Join(work, "file"): "project", filepath.Join(work, ".env"): "secret", filepath.Join(external, "input"): "input"} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(external, "executable")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nprintf executable"), 0o700); err != nil { //nolint:gosec // test-owned executable fixture, no credentials
		t.Fatal(err)
	}
	resolved := resolveStrictFixture(t, work, []config.FileRule{{Path: ".", Access: []string{"read"}, Recursive: true}})
	inputs := []string{filepath.Join(external, "input")}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var output bytes.Buffer
	done := make(chan struct{})
	code, err := Run(ctx, RunOptions{Engine: engine, Directory: work, ResolvedProfile: &resolved, StrictInputs: TrustedRuntimeInputs{Read: inputs, Exec: []string{executable}}, OnStrictRuntimeCapabilities: func(m StrictRuntimeCapabilities) error {
		if len(m.Inputs.Read) != 1 || m.Inputs.Read[0] != inputs[0] {
			t.Error("incorrect capability metadata")
		}
		// Handoff is complete; mutation may now proceed while Run uses its copy.
		go func() {
			defer close(done)
			for i := 0; i < 10000; i++ {
				resolved.Files[0].Access[0] = "write"
				inputs[0] = "/changed"
			}
		}()
		return nil
	}, Args: []string{"/bin/sh", "-c", `set -eu
cat file
cat "$1"
"$2"
if cat .env; then exit 91; fi
if printf modified > file; then exit 92; fi
`, "fixture", filepath.Join(external, "input"), executable}, Stdout: &output, Stderr: &output})
	<-done
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v output=%s", code, err, output.String())
	}
	if data, err := os.ReadFile(filepath.Join(work, "file")); err != nil || string(data) != "project" { //nolint:gosec // test-owned sentinel, not operator input
		t.Fatalf("project modified: %q %v", data, err)
	}
	// Trusted inputs must not bypass the immutable protected preset.
	_, err = Run(ctx, RunOptions{Engine: engine, Directory: work, ResolvedProfile: &config.ResolvedProfile{}, StrictInputs: TrustedRuntimeInputs{Read: []string{filepath.Join(work, ".env")}}, OnStrictRuntimeCapabilities: func(StrictRuntimeCapabilities) error { return nil }, Args: []string{"/bin/true"}})
	if err == nil || !strings.Contains(err.Error(), "trusted input matches protected preset") {
		t.Fatalf("trusted input bypassed protected preset or failed unexpectedly: %v", err)
	}
}
