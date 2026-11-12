package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func replaySnapshot(t *testing.T, path string) ProfileSnapshot {
	t.Helper()
	data, err := json.Marshal(Profile{Version: 1, Name: "build", Files: []FileRule{{Path: path, Access: []string{"read"}, Recursive: true}}, Network: []NetworkRule{}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseProfileSnapshot("build", data)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestResolveProfileCeilingsSymlinksAndProtectedPaths(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, ".sydguard"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "missing"), filepath.Join(root, "dangling")); err != nil {
		t.Fatal(err)
	}
	project, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"src", "src/new/deeper"} {
		r, err := ResolveProfile(replaySnapshot(t, path), project, home, []string{project}, []string{filepath.Join(project, ".sydguard")})
		if err != nil {
			t.Fatal(err)
		}
		if r.Files[0].Path != filepath.Join(project, path) || !r.Files[0].Recursive {
			t.Fatalf("incorrect resolution: %+v", r)
		}
	}
	for _, path := range []string{".", ".sydguard/default.json", "escape/new", "dangling/new"} {
		if _, err := ResolveProfile(replaySnapshot(t, path), project, home, []string{project}, []string{filepath.Join(project, ".sydguard")}); err == nil {
			t.Errorf("accepted unsafe path %q", path)
		}
	}
	if _, err := ResolveProfile(replaySnapshot(t, "~/file"), project, home, []string{project}, nil); err == nil {
		t.Fatal("tilde escaped ceiling")
	}
	if _, err := ResolveProfile(replaySnapshot(t, "src"), project, home, nil, nil); err == nil {
		t.Fatal("empty ceilings accepted")
	}
}

func TestResolveProfileRejectsTraversalAndUnsafeResolvedNames(t *testing.T) {
	p := Profile{Version: 1, Name: "build", Files: []FileRule{{Path: "link/../file", Access: []string{"read"}}}}
	data, _ := json.Marshal(p)
	if _, err := ParseProfileSnapshot("build", data); err == nil {
		t.Fatal("parent traversal accepted")
	}
	root := t.TempDir()
	target := filepath.Join(root, "wild*name")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveProfile(replaySnapshot(t, "link"), root, "", []string{root}, nil); err == nil {
		t.Fatal("unsafe resolved literal accepted")
	}
}

func TestResolveProfileRejectsRootAfterSymlinkResolution(t *testing.T) {
	root := t.TempDir()
	if err := os.Symlink("/", filepath.Join(root, "root")); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveProfile(replaySnapshot(t, "root"), root, "", []string{"/"}, nil); err == nil {
		t.Fatal("resolved root accepted")
	}
}
