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

	"github.com/Gobd/syd-guard/internal/config"
)

func TestStrictProfileReplayIntegration(t *testing.T) {
	engine := os.Getenv("SYDGUARD_TEST_SYD")
	if runtime.GOOS != "linux" || engine == "" {
		t.Skip("requires Linux and explicit Syd 3.59.0")
	}
	version, err := exec.Command(engine, "--version").Output() //nolint:gosec // explicit candidate and fixed diagnostic
	if err != nil || !strings.HasPrefix(string(version), "syd 3.59.0 ") {
		t.Fatalf("unexpected candidate version: %q %v", version, err)
	}
	cases := []struct {
		name   string
		rules  []config.FileRule
		script string
	}{
		{"read", []config.FileRule{{Path: ".", Access: []string{"read"}, Recursive: true}}, `set -eu
cat file
if printf changed > file; then exit 91; fi
if printf created > created; then exit 92; fi
if rm file; then exit 93; fi
if mv file moved; then exit 94; fi
`},
		{"write-no-delete", []config.FileRule{{Path: ".", Access: []string{"read", "write"}, Recursive: true}}, `set -eu
printf changed > file
printf created > created
chmod 600 file
mkdir scratch
ln -s file shortcut
if rm file; then exit 91; fi
if mv file moved; then exit 92; fi
`},
		{"write-only", []config.FileRule{{Path: ".", Access: []string{"write"}, Recursive: true}}, `set -eu
printf changed > file
printf created > created
chmod 600 file
mkdir scratch
ln -s file shortcut
if cat file; then exit 91; fi
if rm file; then exit 92; fi
`},
		{"delete-only", []config.FileRule{{Path: ".", Access: []string{"delete"}, Recursive: true}}, `set -eu
rm file
if cat dir/file; then exit 91; fi
if printf created > created; then exit 92; fi
`},
		{"full", []config.FileRule{{Path: ".", Access: []string{"read", "write", "delete"}, Recursive: true}}, `set -eu
printf changed > file
printf created > created
mv created moved
rm moved
mkdir newdir
rmdir newdir
if cat .env; then exit 91; fi
if printf changed > .env; then exit 92; fi
cat .sydguard/default.json
if printf changed > .sydguard/default.json; then exit 93; fi
if mv .sydguard moved-policy; then exit 94; fi
if ln .sydguard/default.json policy-hardlink; then exit 98; fi
if stat /dev/syd/allow/write+/***; then exit 95; fi
if ./localexec; then exit 96; fi
if printf changed > "$1"; then exit 97; fi
`},
		{"exact-files", []config.FileRule{{Path: "file", Access: []string{"read", "write"}}, {Path: "created", Access: []string{"write"}}}, `set -eu
cat file
printf changed > file
printf created > created
if cat dir/file; then exit 91; fi
if printf changed > other; then exit 92; fi
`},
		{"exact", []config.FileRule{{Path: "dir", Access: []string{"read"}}}, `set -eu
if cat dir/file; then exit 91; fi
`},
		{"recursive", []config.FileRule{{Path: "dir", Access: []string{"read"}, Recursive: true}}, `set -eu
cat dir/file
`},
		{"empty", nil, `set -eu
if cat file; then exit 91; fi
if printf changed > file; then exit 92; fi
if printf created > created; then exit 93; fi
`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			work, temporary, authority := t.TempDir(), t.TempDir(), t.TempDir()
			if err := os.Chmod(authority, 0o700); err != nil { //nolint:gosec // private test profile directory
				t.Fatal(err)
			}
			for name, content := range map[string]string{"file": "original", "dir/file": "nested", ".env": "secret", ".sydguard/default.json": "policy"} {
				path := filepath.Join(work, name)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(work, "localexec"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { //nolint:gosec // disposable executable fixture
				t.Fatal(err)
			}
			resolved := resolveStrictFixture(t, work, tc.rules)
			profile, err := StrictProfile(work, temporary, []string{authority, engine}, resolved)
			if err != nil {
				t.Fatal(err)
			}
			protectedEngineFixture := filepath.Join(authority, "engine-fixture")
			if err := os.WriteFile(protectedEngineFixture, []byte("fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(authority, "strict.syd-3")
			if err := os.WriteFile(path, []byte(profile), 0o600); err != nil { //nolint:gosec // private test-owned authority path
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, engine, "-P", path, "--", "/bin/sh", "-c", tc.script, "fixture", protectedEngineFixture) //nolint:gosec // selected candidate and fixed fixture
			command.Dir = work
			command.Env = append(os.Environ(), "TMPDIR="+temporary)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("replay: %v\n%s\nprofile:\n%s", err, output, profile)
			}
		})
	}
}
