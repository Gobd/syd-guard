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

func TestRunStrictProfileIntegration(t *testing.T) {
	engine := os.Getenv("SYDGUARD_TEST_SYD")
	if runtime.GOOS != "linux" || engine == "" {
		t.Skip("requires Linux and explicit Syd 3.59.0")
	}
	home, work := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
	if err := os.WriteFile(filepath.Join(work, "file"), []byte("readable"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolved := resolveStrictFixture(t, work, []config.FileRule{{Path: ".", Access: []string{"read"}, Recursive: true}})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var output bytes.Buffer
	code, err := Run(ctx, RunOptions{
		Engine: engine, Directory: work, ResolvedProfile: &resolved,
		Args: []string{"/bin/sh", "-c", `set -eu
cat file
if printf x > file; then exit 91; fi
if /bin/sh -c 'printf forge >&3'; then exit 92; fi
`},
		Stdout: &output, Stderr: &output, OnEvent: func([]byte) error { return nil },
	})
	if err != nil || code != 0 {
		t.Fatalf("strict Run failed: code=%d err=%v output=%s", code, err, output.String())
	}
	data, err := os.ReadFile(filepath.Join(work, "file")) //nolint:gosec // test-owned file
	if err != nil || string(data) != "readable" {
		t.Fatalf("strict file changed: %q %v", data, err)
	}
	code, err = Run(ctx, RunOptions{Engine: engine, Directory: work, Args: []string{"/bin/sh", "-c", "printf legacy > legacy"}, Stdout: &output, Stderr: &output})
	if err != nil || code != 0 {
		t.Fatalf("legacy Run failed: code=%d err=%v output=%s", code, err, output.String())
	}
	if data, err := os.ReadFile(filepath.Join(work, "legacy")); err != nil || string(data) != "legacy" { //nolint:gosec // test-owned file
		t.Fatalf("nil profile did not preserve legacy writes: %q %v", data, err)
	}
}
