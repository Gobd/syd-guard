package syd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Gobd/syd-guard/internal/config"
)

func resolveStrictFixture(t *testing.T, work string, files []config.FileRule) config.ResolvedProfile {
	t.Helper()
	if files == nil {
		files = []config.FileRule{}
	}
	data, err := json.Marshal(config.Profile{Version: 1, Name: "fixture", Files: files, Network: []config.NetworkRule{}})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := config.ParseProfileSnapshot("fixture", data)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := config.ResolveProfile(snapshot, work, "", []string{work}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func TestStrictProfileCompilation(t *testing.T) {
	work, temporary := t.TempDir(), t.TempDir()
	resolved := resolveStrictFixture(t, work, []config.FileRule{{Path: ".", Access: []string{"read", "write", "delete"}, Recursive: true}})
	work = resolved.Files[0].Path
	temporary, _ = filepath.EvalSymlinks(temporary)
	profile, err := StrictProfile(work, temporary, nil, resolved)
	if err != nil {
		t.Fatal(err)
	}
	grant := "allow/read,stat,readdir,chdir,readlink,write,create,truncate,chmod,chattr,mkdir,symlink,delete,rmdir,rename+" + work + "/***"
	if !strings.Contains(profile, grant) {
		t.Fatalf("missing grouped grant %q", grant)
	}
	if strings.Contains(profile, "symlink,exec+"+work) || strings.Contains(profile, "symlink,exec+"+temporary) {
		t.Fatal("write rules granted execution")
	}
	if strings.LastIndex(profile, "deny/write,create,delete,rename") < strings.Index(profile, grant) {
		t.Fatal("protected policy deny precedes grants")
	}
	empty, err := StrictProfile(work, temporary, nil, config.ResolvedProfile{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(empty, "allow/read,stat,readdir,readlink,chdir,write,create,delete,rename,truncate,chmod,chattr,mkdir,rmdir,symlink+"+work) {
		t.Fatal("empty strict profile granted project writes")
	}
}

func TestStrictProfileRejectsChangedAndInvalidRules(t *testing.T) {
	work, temporary, outside := t.TempDir(), t.TempDir(), t.TempDir()
	path := filepath.Join(work, "new")
	for _, rule := range []config.FileRule{
		{Path: "/", Access: []string{"read"}},
		{Path: path + "\t", Access: []string{"read"}},
		{Path: path + "*", Access: []string{"read"}},
		{Path: path, Access: []string{"exec"}},
		{Path: path, Access: []string{"write", "write"}},
	} {
		if _, err := StrictProfile(work, temporary, nil, config.ResolvedProfile{Files: []config.FileRule{rule}}); err == nil {
			t.Errorf("accepted %+v", rule)
		}
	}
	resolved := resolveStrictFixture(t, work, []config.FileRule{{Path: "new/file", Access: []string{"read"}}})
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if _, err := StrictProfile(work, temporary, nil, resolved); err == nil {
		t.Fatal("accepted replaced prefix")
	}
	if _, err := StrictProfile(work, work, nil, config.ResolvedProfile{}); err == nil {
		t.Fatal("accepted project as temporary directory")
	}
}

func TestStrictProfileRejectsWritableWholeHomeAndProtectedOverlap(t *testing.T) {
	work, temporary, home := t.TempDir(), t.TempDir(), t.TempDir()
	home, err := filepath.EvalSymlinks(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for _, access := range [][]string{{"write"}, {"delete"}} {
		if _, err := StrictProfile(work, temporary, nil, config.ResolvedProfile{Files: []config.FileRule{{Path: home, Access: access, Recursive: true}}}); err == nil {
			t.Fatalf("accepted writable home: %v", access)
		}
		runtimePath, err := filepath.EvalSymlinks("/usr")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := StrictProfile(work, temporary, nil, config.ResolvedProfile{Files: []config.FileRule{{Path: filepath.Join(runtimePath, "fixture"), Access: access}}}); err == nil {
			t.Fatalf("accepted mutation within trusted executable runtime: %v", access)
		}
	}
	resolved := resolveStrictFixture(t, work, []config.FileRule{{Path: ".", Access: []string{"read"}, Recursive: true}})
	if _, err := StrictProfile(work, temporary, []string{filepath.Join(resolved.Files[0].Path, "authority")}, resolved); err == nil {
		t.Fatal("accepted protected authority overlap")
	}
}
