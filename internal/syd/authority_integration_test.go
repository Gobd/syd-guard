package syd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/config"
)

// A credential authority created under configuration A must stay protected when
// a launcher selects configuration B and grants the surrounding workspace.
func TestPrivateAuthorityDifferentXDGIntegration(t *testing.T) {
	engine := os.Getenv("SYDGUARD_TEST_SYD")
	if runtime.GOOS != "linux" || engine == "" {
		t.Skip("requires Linux and explicit static Syd")
	}
	work, home := t.TempDir(), t.TempDir()
	authority := filepath.Join(work, "config-a", "sydguard", "state", config.PrivateAuthorityFolder)
	if err := os.MkdirAll(authority, 0o700); err != nil {
		t.Fatal(err)
	}
	credential := filepath.Join(authority, "managed-credential")
	if err := os.WriteFile(credential, []byte("test-owned-authority-canary"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config-b"))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var output bytes.Buffer
	code, err := Run(ctx, RunOptions{
		Engine: engine, Directory: work,
		Args: []string{"/bin/sh", "-c", `set -eu
printf allowed > ordinary
if cat "$1"; then exit 91; fi
if stat "$1"; then exit 92; fi
if printf changed > "$1"; then exit 93; fi
if ln "$1" authority-alias; then exit 94; fi
printf AUTHORITY_PASS
`, "fixture", credential}, Stdout: &output, Stderr: &output,
	})
	if err != nil || code != 0 || !bytes.Contains(output.Bytes(), []byte("AUTHORITY_PASS")) {
		t.Fatalf("alternate-XDG authority protection: code=%d err=%v output=%s", code, err, &output)
	}
	data, err := os.ReadFile(credential) //nolint:gosec // test-owned canary
	if err != nil || string(data) != "test-owned-authority-canary" {
		t.Fatalf("authority changed: %q %v", data, err)
	}
}
