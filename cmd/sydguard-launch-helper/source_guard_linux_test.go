//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/managedlaunch"
	"golang.org/x/sys/unix"
)

func testDirectory(t *testing.T, path string) *os.File {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path) //nolint:gosec // test-owned directory
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func testRootID(t *testing.T) directoryID {
	t.Helper()
	f, err := os.Open("/")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	id, err := sourceAncestryOps.stat(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestWritableSourceFDRejectsRelocatedRuntimeOverlap(t *testing.T) {
	base := t.TempDir()
	runtime := testDirectory(t, filepath.Join(base, "runtime"))
	project := testDirectory(t, filepath.Join(base, "runtime", "local", "project"))
	disjoint := testDirectory(t, filepath.Join(base, "separate", "project"))
	home := testDirectory(t, filepath.Join(base, "home"))
	profile := config.Profile{Files: []config.FileRule{{Path: ".", Access: []string{"write"}, Recursive: true}}}
	root := testRootID(t)
	check := func(f *os.File) error {
		return validateWritableSourceFDs(int(f.Fd()), profile, root, []int{int(runtime.Fd())}, int(home.Fd()), sourceAncestryOps)
	}
	// The presentation at /run/.../project is not passed to the FD guard.
	if err := check(project); err == nil || !strings.Contains(err.Error(), "runtime") {
		t.Fatalf("runtime source accepted: %v", err)
	}
	if err := check(runtime); err == nil {
		t.Fatal("identical runtime root accepted")
	}
	parent := testDirectory(t, base)
	if err := check(parent); err == nil {
		t.Fatal("runtime ancestor accepted")
	}
	if err := check(disjoint); err != nil {
		t.Fatalf("disjoint project rejected: %v", err)
	}
}

func TestWritableSourceFDWholeHomeRules(t *testing.T) {
	base := t.TempDir()
	project := testDirectory(t, filepath.Join(base, "project"))
	home := testDirectory(t, filepath.Join(base, "project", "home"))
	testDirectory(t, filepath.Join(base, "project", "home", "sub"))
	runtime := testDirectory(t, filepath.Join(base, "runtime"))
	root := testRootID(t)
	for _, tc := range []struct {
		path      string
		recursive bool
		reject    bool
	}{
		{"home", false, true},
		{".", true, true},
		{".", false, false},
		{"home/sub", true, false},
		{"missing", true, false},
	} {
		t.Run(tc.path+strconvBool(tc.recursive), func(t *testing.T) {
			profile := config.Profile{Files: []config.FileRule{{Path: tc.path, Access: []string{"write"}, Recursive: tc.recursive}}}
			err := validateWritableSourceFDs(int(project.Fd()), profile, root, []int{int(runtime.Fd())}, int(home.Fd()), sourceAncestryOps)
			if (err != nil) != tc.reject {
				t.Fatalf("error=%v reject=%t", err, tc.reject)
			}
		})
	}
}

func strconvBool(v bool) string {
	if v {
		return "-recursive"
	}
	return "-exact"
}

func TestWritableSourceUsesAccountHomeNotRequest(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test requires an unprivileged account")
	}
	rootFD, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(rootFD) }()
	home, err := accountHome(rootFD, uint32(os.Getuid())) //nolint:gosec // Linux UIDs fit uint32
	if err != nil {
		t.Skipf("local passwd home unavailable: %v", err)
	}
	fd, err := unix.Open(home, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("account home unavailable: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()
	request := managedlaunch.Request{Home: t.TempDir()}
	if request.Home == home {
		t.Fatal("fake home unexpectedly matches account")
	}
	projectFD, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		t.Fatal(err)
	}
	project := os.NewFile(uintptr(projectFD), "account-home")
	defer func() { _ = project.Close() }()
	profile := config.Profile{Files: []config.FileRule{{Path: ".", Access: []string{"delete"}, Recursive: true}}}
	if err := validateWritableSource(project, profile, uint32(os.Getuid())); err == nil || !strings.Contains(err.Error(), "whole-home") { //nolint:gosec // Linux UIDs fit uint32
		t.Fatalf("actual home accepted with fake request home %q: %v", request.Home, err)
	}
}

func TestDirectoryAncestryFailsClosedAndClosesFDs(t *testing.T) {
	for _, tc := range []struct {
		name      string
		parents   map[int]int
		failAt    int
		wantError bool
	}{
		{"root", map[int]int{1: 0}, -1, false},
		{"disconnected", map[int]int{1: 1}, -1, true},
		{"loop", map[int]int{1: 2, 2: 1}, -1, true},
		{"missing-parent", map[int]int{}, 1, true},
		{"depth-limit", nil, -1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nextFD := 1000
			open := map[int]int{10: 1}
			ops := ancestryOps{}
			ops.dup = func(fd int) (int, error) { nextFD++; open[nextFD] = open[fd]; return nextFD, nil }
			ops.stat = func(fd int) (directoryID, error) {
				return directoryID{1, uint64(open[fd] + 1)}, nil //nolint:gosec // synthetic IDs are nonnegative and bounded
			}
			ops.parent = func(fd int) (int, error) {
				id := open[fd]
				if id == tc.failAt {
					return -1, unix.ENOENT
				}
				parent := id + 1
				if tc.parents != nil {
					var ok bool
					parent, ok = tc.parents[id]
					if !ok {
						return -1, errors.New("missing parent")
					}
				}
				nextFD++
				open[nextFD] = parent
				return nextFD, nil
			}
			ops.close = func(fd int) error { delete(open, fd); return nil }
			_, err := directoryAncestry(10, directoryID{1, 1}, ops)
			if (err != nil) != tc.wantError {
				t.Fatalf("error=%v", err)
			}
			if len(open) != 1 {
				t.Fatalf("leaked descriptors: %v", open)
			}
		})
	}
}
