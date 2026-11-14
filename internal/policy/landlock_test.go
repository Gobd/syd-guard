package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Gobd/syd-guard/internal/system"
)

func TestLandlockCeiling(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	outside, _ = filepath.EvalSymlinks(outside)
	l := Landlock{Enabled: true, Read: []string{root}, Write: []string{filepath.Join(root, "writable")}}
	if err := os.Mkdir(l.Write[0], 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		kind, path string
		ok         bool
	}{
		{"read", root + "/***", true},
		{"read", root + "/new/file", true},
		{"write", root + "/writable/new/file", true},
		{"write", root + "/other", false},
		{"read", root + "*", false},
		{"read", outside + "/***", false},
		{"hosts", "https://example.com", true},
	} {
		if err := l.Check(tc.kind, tc.path); (err == nil) != tc.ok {
			t.Errorf("%s %s: %v", tc.kind, tc.path, err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := l.Check("read", root+"/escape/new/file"); err == nil {
		t.Fatal("symlink escape passed ceiling check")
	}
	if err := (Landlock{}).Check("write", "/***"); err != nil {
		t.Fatal("default must permit arbitrary Syd approvals", err)
	}
}

func TestLandlockCommandsDistinguishFilesAndDirectories(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	l := Landlock{Enabled: true, Read: []string{file}, Write: []string{dir}}
	cmds, err := l.Commands()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(cmds, "\n")
	for _, want := range []string{"sandbox/lock:on", "default/lock:kill", "allow/lock/read+" + file, "allow/lock/readdir+" + dir, "allow/lock/create+" + dir, "allow/lock/connect+0-65535"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(joined, "allow/lock/readdir+"+file) {
		t.Fatal("directory-only right assigned to a file")
	}
	if cmds, err := (Landlock{}).Commands(); err != nil || len(cmds) != 0 {
		t.Fatal("disabled ceiling emitted commands")
	}
}

func TestLandlockRootValidation(t *testing.T) {
	for _, path := range []string{"relative", "/x/../y", "/x/***", "/x/$HOME", "/x\nallow/all"} {
		if err := (Landlock{Read: []string{path}}).Validate(); err == nil {
			t.Errorf("accepted %q", path)
		}
	}
	project := t.TempDir()
	if _, err := ResolveLandlock(Landlock{Enabled: true, Write: []string{filepath.Join(project, "missing")}}, project, nil); err == nil {
		t.Fatal("missing configured root silently ignored")
	}
	ceiling, err := ResolveLandlock(Landlock{Enabled: true}, project, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ceiling.Check("write", project+"/***"); err != nil {
		t.Fatal("project baseline not inside ceiling", err)
	}
}

// A saved rule outside the ceiling is skipped for the session, not fatal.
func TestCompileSkipsRulesOutsideCeiling(t *testing.T) {
	project := t.TempDir()
	inside := t.TempDir()
	in := ProfileInput{
		Project: project, IPC: "@x", ProxyPort: 4000, Protect: ProtectedFor(project),
		Landlock: Landlock{Enabled: true, Read: []string{inside}},
		// Home isn't in the baseline (unlike /opt, /tmp): outside the ceiling.
		Rules: []Rules{{Read: []string{inside + "/***", system.Home() + "/.sydguard-outside-test/***"}}},
	}
	resolved, err := ResolveLandlock(in.Landlock, project, nil)
	if err != nil {
		t.Fatal(err)
	}
	in.Landlock = resolved
	prof, err := CompileProfile(in)
	if err != nil {
		t.Fatalf("session must still start: %v", err)
	}
	if !strings.Contains(prof, inside+"/***") || strings.Contains(prof, ".sydguard-outside-test") {
		t.Errorf("inside rule must be applied, outside rule skipped:\n%s", prof)
	}
}
