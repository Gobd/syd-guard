//go:build linux

package managedstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// No root test process: inject syscall failures at the publication seam using
// only files owned by this unprivileged test UID.
func TestPublicationFailuresAndIdentityCleanup(t *testing.T) {
	for _, scenario := range []struct {
		name          string
		fail          string
		replace       bool
		indeterminate bool
		published     bool
	}{
		{"create-file-sync", "file", false, false, false},
		{"create-rename", "rename", false, false, false},
		{"create-dir-sync", "directory", false, true, true},
		{"replace-file-sync", "file", true, false, false},
		{"replace-rename", "rename", true, false, false},
		{"replace-dir-sync", "directory", true, true, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			dir := t.TempDir()
			df, err := os.Open(dir) //nolint:gosec // test-owned temporary directory
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = df.Close() }()
			stage := filepath.Join(dir, ".file-test")
			f, err := os.OpenFile(stage, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600) //nolint:gosec // test-owned temporary path
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			if _, err := f.WriteString("desired"); err != nil {
				t.Fatal(err)
			}
			var own unix.Stat_t
			if err := unix.Fstat(int(f.Fd()), &own); err != nil {
				t.Fatal(err)
			}
			if scenario.replace {
				if err := os.WriteFile(filepath.Join(dir, "profile"), []byte("previous"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			ops := publicationOps{
				syncFile: func(f *os.File) error {
					if scenario.fail == "file" {
						return unix.EIO
					}
					return f.Sync()
				},
				rename: func(fd int, stage, name string, replace bool) error {
					if scenario.fail == "rename" {
						return unix.EIO
					}
					if replace {
						return unix.Renameat(fd, stage, fd, name)
					}
					return unix.Renameat2(fd, stage, fd, name, unix.RENAME_NOREPLACE)
				},
				syncDir: func(fd int) error {
					if scenario.fail == "directory" {
						return unix.EIO
					}
					return unix.Fsync(fd)
				},
			}
			err = publishStaged(int(df.Fd()), ".file-test", "profile", f, scenario.replace, ops)
			if err == nil || errors.Is(err, ErrIndeterminate) != scenario.indeterminate {
				t.Fatalf("outcome: %v", err)
			}
			cleanupStage(int(df.Fd()), ".file-test", own)
			if _, err := os.Lstat(stage); !os.IsNotExist(err) {
				t.Fatalf("own stage remains: %v", err)
			}
			data, err := os.ReadFile(filepath.Join(dir, "profile")) //nolint:gosec // test-owned temporary path
			switch {
			case scenario.published:
				if err != nil || string(data) != "desired" {
					t.Fatalf("published: %q %v", data, err)
				}
			case scenario.replace:
				if err != nil || string(data) != "previous" {
					t.Fatalf("previous changed: %q %v", data, err)
				}
			default:
				if !os.IsNotExist(err) {
					t.Fatalf("unexpected publication: %v", err)
				}
			}
		})
	}
}

func TestCleanupStageDoesNotRemoveReplacement(t *testing.T) {
	dir := t.TempDir()
	df, err := os.Open(dir) //nolint:gosec // test-owned temporary directory
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = df.Close() }()
	path := filepath.Join(dir, ".file-test")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600) //nolint:gosec // test-owned temporary path
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var own unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &own); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	cleanupStage(int(df.Fd()), ".file-test", own)
	b, err := os.ReadFile(path) //nolint:gosec // test-owned temporary path
	if err != nil || string(b) != "replacement" {
		t.Fatalf("replacement removed: %q %v", b, err)
	}
}
