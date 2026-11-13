//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/managedlaunch"
	"github.com/Gobd/syd-guard/internal/managedlive"
	"golang.org/x/sys/unix"
)

func TestLiveEngineWrongDigestPreservesOffset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine")
	if err := os.WriteFile(path, engineELF(false), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var st unix.Stat_t
	if err = unix.Fstat(int(f.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	if _, err = f.Seek(17, 0); err != nil {
		t.Fatal(err)
	}
	if err = checkLiveEngine(f, st, uint32(os.Getuid())); err == nil {
		t.Fatal("wrong engine accepted")
	}
	off, err := f.Seek(0, 1)
	if err != nil || off != 17 {
		t.Fatalf("engine offset changed: %d %v", off, err)
	}
}
func TestLiveAuthorityPinsAndWholeWritableCeiling(t *testing.T) {
	a, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err = samePinnedDirectory(a, a); err != nil {
		t.Fatal(err)
	}
	if err = samePinnedDirectory(a, b); err == nil {
		t.Fatal("different directory accepted")
	}
	p := liveWritableCeiling()
	w, err := managedlaunch.ValidateIntent(p)
	if err != nil || !w || len(p.Files) != 1 || p.Files[0].Path != "." || !p.Files[0].Recursive || strings.Join(p.Files[0].Access, ",") != "read,write,delete" {
		t.Fatalf("invalid ceiling: %+v %v", p, err)
	}
}
func TestLiveWatchDeadlineExactCompletion(t *testing.T) {
	now := time.Unix(100, 0)
	id := strings.Repeat("a", 64)
	other := strings.Repeat("b", 64)
	var w liveWatchDeadline
	if err := w.arm(id, 1, true, now); err != nil {
		t.Fatal(err)
	}
	if w.deadline != now.Add(managedlive.StartupTimeout) {
		t.Fatal(w.deadline)
	}
	if err := w.arm(other, 2, false, now); err == nil {
		t.Fatal("overlapping arm")
	}
	if err := w.complete(other, 1, now); err == nil {
		t.Fatal("wrong request")
	}
	if w.deadline != now.Add(managedlive.StartupTimeout) {
		t.Fatal("renewed deadline")
	}
	if err := w.complete(id, 1, now.Add(managedlive.StartupTimeout)); err == nil || !w.expired(now.Add(managedlive.StartupTimeout)) {
		t.Fatal("expired completion")
	}
	w = liveWatchDeadline{}
	if err := w.arm(id, 2, false, now); err != nil {
		t.Fatal(err)
	}
	if w.deadline != now.Add(managedlive.UpdateTimeout) {
		t.Fatal(w.deadline)
	}
	if err := w.complete(id, 2, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if w.expired(now.Add(time.Hour)) {
		t.Fatal("completed deadline remains armed")
	}
}
