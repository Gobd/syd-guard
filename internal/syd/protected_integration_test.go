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

func TestProtectedPresetIntegration(t *testing.T) {
	engine := os.Getenv("SYDGUARD_TEST_SYD")
	if runtime.GOOS != "linux" || engine == "" {
		t.Skip("requires Linux and explicit tested Syd")
	}
	work, temp, authority := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.Chmod(authority, 0o700); err != nil { //nolint:gosec // private directory needs search permission
		t.Fatal(err)
	}
	for _, name := range []string{".env", "example.env", ".env.local", "one/.env", "one/example.env", "one/.env.local", "one/two/.env", "one/two/example.env", "one/two/.env.local", ".ssh/key", ".aws/credentials", ".config/google-chrome/Default/Login Data", ".sydguard/default.json"} {
		path := filepath.Join(work, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(work, "one/two/.env"), filepath.Join(work, "alias")); err != nil {
		t.Fatal(err)
	}
	profile, err := Profile(work, temp, []string{authority})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(authority, "profile.syd-3")
	if err := os.WriteFile(path, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	script := `set -eu
for f in .env example.env .env.local one/.env one/example.env one/.env.local one/two/.env one/two/example.env one/two/.env.local .ssh/key .aws/credentials '.config/google-chrome/Default/Login Data' alias; do
 if cat "$f"; then echo "READ_BYPASS:$f"; exit 91; fi
 if stat -L "$f"; then echo "STAT_BYPASS:$f"; exit 92; fi
done
cat .sydguard/default.json
if printf x > .sydguard/default.json; then exit 93; fi
if mv .sydguard changed; then exit 94; fi
if mv "$PWD" "$PWD-renamed"; then exit 97; fi
if ln .env new-hardlink; then exit 95; fi
if ln -s .env new-symlink && cat new-symlink; then exit 96; fi
printf PRESET_PASS
`
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, engine, "-P", path, "--", "/bin/sh", "-c", script) //nolint:gosec // fixed test-owned fixture
	cmd.Dir = work
	output, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "PRESET_PASS") {
		t.Fatalf("preset failed: %v\n%s", err, output)
	}
}

// This gate deliberately expects an inode boundary, not merely a name rule.
// A preexisting hardlink with an unrelated name is currently a known bypass.
func TestProtectedPresetPreexistingHardlinkIntegration(t *testing.T) {
	engine := os.Getenv("SYDGUARD_TEST_SYD")
	if runtime.GOOS != "linux" || engine == "" {
		t.Skip("requires Linux and explicit tested Syd")
	}
	work, temp, authority := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.Chmod(authority, 0o700); err != nil { //nolint:gosec // private profile directory needs search permission
		t.Fatal(err)
	}
	secret := filepath.Join(work, ".env")
	alias := filepath.Join(work, "ordinary-file")
	if err := os.WriteFile(secret, []byte("test-owned fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(secret, alias); err != nil {
		t.Fatal(err)
	}
	profile, err := Profile(work, temp, []string{authority})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(authority, "profile.syd-3")
	if err := os.WriteFile(path, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, engine, "-P", path, "--", "/bin/cat", alias) //nolint:gosec // selected engine and test-owned fixture paths
	cmd.Dir = work
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("preexisting hardlink bypassed secret protection: %s", output)
	}
	if _, ok := err.(*exec.ExitError); !ok || !strings.Contains(string(output), "Permission denied") {
		t.Fatalf("fixture failed without demonstrating a denied read: %v %s", err, output)
	}
}
