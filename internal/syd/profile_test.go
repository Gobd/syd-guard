package syd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProfileIsImmutableAndNoNetwork(t *testing.T) {
	work, temporary := t.TempDir(), t.TempDir()
	protected := filepath.Join(work, "authority")
	profile, err := Profile(work, temporary, []string{protected})
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"include_profile fs", "allow/lock/", "deny/all+" + protected, "create,delete,rename,truncate"} {
		if !strings.Contains(profile, required) {
			t.Fatalf("missing %q", required)
		}
	}
	// The operator-approved standard-toolchain exception is exact, not a
	// blanket allowance for other unsafe execution/enforcement overrides.
	if !strings.Contains(profile, "trace/allow_unsafe_exec_nopie:1\n") {
		t.Fatal("missing explicit non-PIE compatibility setting")
	}
	withoutCompatibility := strings.ReplaceAll(profile, "trace/allow_unsafe_exec_nopie:1\n", "")
	for _, forbidden := range []string{"lock:off", "allow/net", "allow/cnet", "include_profile user", "allow_unsafe"} {
		if strings.Contains(withoutCompatibility, forbidden) {
			t.Fatalf("unexpected unsafe/broad option %q", forbidden)
		}
	}
}

func TestRejectRuleInjectionAndBroadWorkspaces(t *testing.T) {
	for _, path := range []string{"relative", "/tmp/a\nlock:off", "/tmp/a*", "/tmp/a?", "/tmp/a[0]", "/tmp/a\\b"} {
		if literalPath(path) == nil {
			t.Fatalf("accepted unsafe literal %q", path)
		}
	}
	if _, err := Profile("/", t.TempDir(), nil); err == nil {
		t.Fatal("whole-root workspace accepted")
	}
	if _, err := Profile("/tmp", t.TempDir(), nil); err == nil {
		t.Fatal("whole-temp workspace accepted")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	if _, err := Profile(home, t.TempDir(), nil); err == nil {
		t.Fatal("whole-home workspace accepted")
	}
}

func TestCanonicalDirectoryRejectsFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := canonicalDirectory(path); err == nil {
		t.Fatal("file accepted as writable directory")
	}
}
