package syd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// This gate must exercise default engine hardening: no trace/allow_unsafe flags.
func TestImmutableConfinementIntegration(t *testing.T) {
	engine := os.Getenv("SYDGUARD_TEST_SYD")
	if runtime.GOOS != "linux" || engine == "" {
		t.Skip("requires Linux and explicit SYDGUARD_TEST_SYD candidate")
	}
	work, temporary, authority := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.Chmod(authority, 0o700); err != nil { //nolint:gosec // private test directory requires owner search permission, not a file mode
		t.Fatal(err)
	}
	profile, err := Profile(work, temporary, []string{authority})
	if err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(authority, "test.syd-3")
	if err := os.WriteFile(profilePath, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	secret := filepath.Join(authority, "secret")
	if err := os.WriteFile(secret, []byte("not-for-workload"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("must-not-connect")) }))
	defer server.Close()
	// The shell program is a fixed adversarial fixture; paths/URL are argv, not
	// inserted into shell source. Nested sh exercises exec inheritance.
	script := `set -eu
printf allowed > allowed
if printf outside > "$1"; then echo OUTSIDE_WRITE_BYPASS; exit 90; fi
if cat "$2"; then echo AUTHORITY_READ_BYPASS; exit 91; fi
if printf mutate > "$3"; then echo PROFILE_WRITE_BYPASS; exit 92; fi
/bin/sh -c 'if printf child > "$1"; then exit 93; fi' child "$1"
if stat /dev/syd/allow/write+/***; then echo VIRTUAL_API_BYPASS; exit 94; fi
if curl --noproxy '*' --max-time 2 --silent --fail "$4"; then echo NETWORK_BYPASS; exit 95; fi
printf "CONFINEMENT_PASS\n"
`
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, engine, "-P", profilePath, "--", "/bin/sh", "-c", script, "fixture", outside, secret, profilePath, server.URL) //nolint:gosec // explicitly selected upstream candidate and fixed test program; no shell interpolation
	command.Dir = work
	command.Env = append(os.Environ(), "TMPDIR="+temporary)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("candidate confinement failed: %v\n%s\nprofile:\n%s", err, output, profile)
	}
	if !strings.Contains(string(output), "CONFINEMENT_PASS") {
		t.Fatalf("missing success sentinel:\n%s", output)
	}
	if _, err := os.Stat(outside); !os.IsNotExist(err) {
		t.Fatalf("outside file was created: %v", err)
	}
	//nolint:gosec // test-owned private profile path
	if data, err := os.ReadFile(profilePath); err != nil || string(data) != profile {
		t.Fatalf("profile changed: %v", err)
	}
	//nolint:gosec // test-owned sandbox output path
	if data, err := os.ReadFile(filepath.Join(work, "allowed")); err != nil || string(data) != "allowed" {
		t.Fatalf("allowed write failed: %v", err)
	}
}
