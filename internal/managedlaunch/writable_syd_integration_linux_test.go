//go:build linux

package managedlaunch_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/managedlaunch"
	"github.com/Gobd/syd-guard/internal/syd"
)

// Ordinary-UID compiler/file-operation fixture; it does not test root mounts.
func TestSelectedWritableProfileStaticSydIntegration(t *testing.T) {
	engine := os.Getenv("SYDGUARD_TEST_SYD")
	if engine == "" {
		t.Skip("requires explicit static Syd 3.59.0")
	}
	for _, tc := range []struct {
		name   string
		rules  []config.FileRule
		script string
	}{
		{"exact-write-no-delete", []config.FileRule{{Path: "edit", Access: []string{"read", "write"}}, {Path: "created", Access: []string{"write"}}}, `set -eu
printf changed > edit
printf created > created
if rm edit; then exit 91; fi
if mv edit moved; then exit 92; fi
if printf changed > outside; then exit 93; fi
`},
		{"recursive-write-delete", []config.FileRule{{Path: ".", Access: []string{"read", "write", "delete"}, Recursive: true}}, `set -eu
printf changed > edit
printf replacement > created
mv created edit
[ "$(cat edit)" = replacement ]
printf created > created
mv created moved
rm moved
if printf changed > .sydguard/default.json; then exit 91; fi
if mv .sydguard policy-moved; then exit 92; fi
if printf changed > .sydguard-private/secret; then exit 93; fi
if mv "$1/.sydguard" "$1/policy-moved"; then exit 94; fi
if printf changed > "$1/.sydguard/default.json"; then exit 95; fi
if ln -s "$2" escape-link; then
  if printf changed > escape-link; then exit 96; fi
fi
`},
		{"delete-only", []config.FileRule{{Path: "edit", Access: []string{"delete"}}}, `set -eu
rm edit
if printf created > outside; then exit 91; fi
`},
		{"scoped", []config.FileRule{{Path: "scope", Access: []string{"read", "write", "delete"}, Recursive: true}}, `set -eu
printf created > scope/created
mv scope/created scope/moved
rm scope/moved
if printf changed > outside; then exit 91; fi
if rm edit; then exit 92; fi
`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, project, scratch := t.TempDir(), t.TempDir(), t.TempDir()
			alias := filepath.Join(t.TempDir(), "project-alias")
			external := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(external, []byte("external"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(project, alias); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(scratch, 0o700); err != nil { //nolint:gosec // private fixture scratch must be traversable
				t.Fatal(err)
			}
			t.Setenv("HOME", home)
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "config"))
			for name, content := range map[string]string{"edit": "original", "outside": "original", "scope/existing": "original", ".sydguard/default.json": "policy", ".sydguard-private/secret": "private"} {
				path := filepath.Join(project, name)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			data, err := json.Marshal(config.Profile{Version: 1, Name: "default", Files: tc.rules, Network: []config.NetworkRule{}})
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := config.ParseManagedProfileSnapshot("default", data)
			if err != nil {
				t.Fatal(err)
			}
			resolved, err := managedlaunch.SelectedProfile(snapshot, project)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			var output bytes.Buffer
			code, err := syd.Run(ctx, syd.RunOptions{Engine: engine, Directory: project, ResolvedProfile: &resolved, WorkTemporaryRoot: scratch, Args: []string{"/bin/sh", "-c", tc.script, "fixture", alias, external}, Stdout: &output, Stderr: &output, OnStrictRuntimeCapabilities: func(syd.StrictRuntimeCapabilities) error { return nil }})
			if err != nil || code != 0 {
				t.Fatalf("strict run code=%d err=%v output=%s", code, err, output.String())
			}
			if got, err := os.ReadFile(external); err != nil || string(got) != "external" { //nolint:gosec // test-owned external file
				t.Fatalf("external file changed: %q %v", got, err)
			}
			for name, want := range map[string]string{"outside": "original", ".sydguard/default.json": "policy", ".sydguard-private/secret": "private"} {
				got, err := os.ReadFile(filepath.Join(project, name)) //nolint:gosec // test-owned fixture path
				if err != nil || string(got) != want {
					t.Fatalf("%s changed: %q %v", name, got, err)
				}
			}
		})
	}
}
