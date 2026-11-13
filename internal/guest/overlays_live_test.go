package guest

import (
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/Gobd/syd-guard/internal/policy"
)

func TestDiscoverWriteOverlays(t *testing.T) {
	root := t.TempDir()
	file := func(rel string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	file("rust/Cargo.toml")
	file("js/deep/package/package.json")
	file("python/pyproject.toml")
	file("js/node_modules/ignored/package.json")
	file(".git/ignored/package.json")
	targets, err := discoverWriteOverlays(root+"/***", []string{"node_modules", "target", ".venv"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(root, "js/deep/package/node_modules"), filepath.Join(root, "js/node_modules"), filepath.Join(root, "python/.venv"), filepath.Join(root, "rust/target")}
	slices.Sort(want)
	if !slices.Equal(targets, want) {
		t.Fatalf("got %v; want %v", targets, want)
	}
	for _, target := range targets {
		if target == filepath.Join(root, "js/node_modules") {
			continue
		}
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			t.Fatalf("discovery must not create %s", target)
		}
	}
	targets, err = discoverWriteOverlays(filepath.Join(root, "rust/target/artifact"), []string{"target"})
	if err != nil || !slices.Equal(targets, []string{filepath.Join(root, "rust/target")}) {
		t.Fatalf("file grant: %v %v", targets, err)
	}
	targets, err = discoverWriteOverlays(root+"/***", nil)
	if err != nil || len(targets) != 0 {
		t.Fatalf("disabled: %v %v", targets, err)
	}
	if _, err := discoverWriteOverlays("/***", []string{"target"}); err == nil {
		t.Fatal("unbounded scan accepted")
	}
	file("unrelated/target/keep.txt")
	if _, err := discoverWriteOverlays(root+"/***", []string{"target"}); err == nil {
		t.Fatal("unrecognized reserved target was silently exposed")
	}
}

func TestStartupSkipsOverlaysOutsideLandlockCeiling(t *testing.T) {
	project, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "Cargo.toml"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Session{Project: project, RulesFile: filepath.Join(project, ".sydguard.json"), OverlayNames: []string{"target"}, Landlock: policy.Landlock{Enabled: true, Write: []string{project}}}
	if err := initializeOverlays(s, []policy.Rules{{Write: []string{outside + "/***"}}}); err != nil {
		t.Fatal(err)
	}
	if len(s.Overlays)+len(s.DynamicOverlays) != 0 {
		t.Fatal("mounted outside ceiling")
	}
	if _, err := os.Stat(filepath.Join(outside, "target")); !os.IsNotExist(err) {
		t.Fatal("created outside target")
	}
}

func TestUpdateQueueConcurrentSessionEnd(t *testing.T) {
	s := &Session{ID: "test", queue: make(chan applyOp, 64)}
	d := &Daemon{sessions: map[string]*Session{s.ID: s}}
	var workers sync.WaitGroup
	workers.Go(func() {
		for op := range s.queue {
			op.done <- nil
		}
	})
	var requests sync.WaitGroup
	for range 100 {
		requests.Go(func() { _ = d.enqueueUpdate(s, applyOp{}) })
	}
	d.mu.Lock()
	delete(d.sessions, s.ID)
	close(s.queue)
	d.mu.Unlock()
	requests.Wait()
	workers.Wait()
}

func TestDiscoverWriteOverlaysDoesNotFollowSymlinks(t *testing.T) {
	root, external := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(external, "Cargo.toml"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	targets, err := discoverWriteOverlays(root+"/***", []string{"target"})
	if err != nil || len(targets) != 0 {
		t.Fatalf("followed link: %v %v", targets, err)
	}
}
