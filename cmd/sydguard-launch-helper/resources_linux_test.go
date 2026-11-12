//go:build linux

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func writeProbeFixture(t *testing.T, dir string) {
	t.Helper()
	for name, value := range map[string]string{
		"cgroup.type": "domain\n", "cgroup.events": "populated 0\nfrozen 0\n", "cgroup.kill": "untouched",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProbeCgroupCleanup(t *testing.T) {
	cases := []struct {
		name  string
		alter func(t *testing.T, dir string)
		ok    bool
	}{
		{name: "valid empty domain", ok: true},
		{name: "threaded", alter: func(t *testing.T, d string) { writeProbeFile(t, d, "cgroup.type", "threaded\n") }},
		{name: "domain threaded", alter: func(t *testing.T, d string) { writeProbeFile(t, d, "cgroup.type", "domain threaded\n") }},
		{name: "invalid type", alter: func(t *testing.T, d string) { writeProbeFile(t, d, "cgroup.type", "domain invalid\n") }},
		{name: "oversized type", alter: func(t *testing.T, d string) { writeProbeFile(t, d, "cgroup.type", strings.Repeat("x", 4097)) }},
		{name: "populated", alter: func(t *testing.T, d string) { writeProbeFile(t, d, "cgroup.events", "populated 1\nfrozen 0\n") }},
		{name: "missing populated", alter: func(t *testing.T, d string) { writeProbeFile(t, d, "cgroup.events", "frozen 0\n") }},
		{name: "duplicate populated", alter: func(t *testing.T, d string) { writeProbeFile(t, d, "cgroup.events", "populated 0\npopulated 0\n") }},
		{name: "malformed event", alter: func(t *testing.T, d string) { writeProbeFile(t, d, "cgroup.events", "populated 0\nfrozen nope\n") }},
		{name: "invalid frozen state", alter: func(t *testing.T, d string) { writeProbeFile(t, d, "cgroup.events", "populated 0\nfrozen 2\n") }},
		{name: "extra event field", alter: func(t *testing.T, d string) { writeProbeFile(t, d, "cgroup.events", "populated 0 extra\n") }},
		{name: "unterminated event", alter: func(t *testing.T, d string) { writeProbeFile(t, d, "cgroup.events", "populated 0") }},
		{name: "oversized events", alter: func(t *testing.T, d string) {
			writeProbeFile(t, d, "cgroup.events", "populated 0\n"+strings.Repeat("x", 4097))
		}},
		{name: "missing kill", alter: func(t *testing.T, d string) { removeProbeFile(t, d, "cgroup.kill") }},
		{name: "missing type", alter: func(t *testing.T, d string) { removeProbeFile(t, d, "cgroup.type") }},
		{name: "missing events", alter: func(t *testing.T, d string) { removeProbeFile(t, d, "cgroup.events") }},
		{name: "symlink kill", alter: func(t *testing.T, d string) { symlinkProbeFile(t, d, "cgroup.kill") }},
		{name: "symlink type", alter: func(t *testing.T, d string) { symlinkProbeFile(t, d, "cgroup.type") }},
		{name: "symlink events", alter: func(t *testing.T, d string) { symlinkProbeFile(t, d, "cgroup.events") }},
		{name: "directory kill", alter: func(t *testing.T, d string) {
			removeProbeFile(t, d, "cgroup.kill")
			if err := os.Mkdir(filepath.Join(d, "cgroup.kill"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "writable interface", alter: func(t *testing.T, d string) {
			if err := os.Chmod(filepath.Join(d, "cgroup.events"), 0o666); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			writeProbeFixture(t, dir)
			if tc.alter != nil {
				tc.alter(t, dir)
			}
			fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = unix.Close(fd) }()
			err = probeCgroupCleanup(fd, time.Second)
			if (err == nil) != tc.ok {
				var st unix.Stat_t
				_ = unix.Fstat(fd, &st)
				t.Fatalf("probe error = %v, want success %t (mode %#o)", err, tc.ok, st.Mode)
			}
			if tc.ok {
				data, err := os.ReadFile(filepath.Join(dir, "cgroup.kill"))
				if err != nil || string(data) != "untouched" {
					t.Fatalf("kill changed: %q, %v", data, err)
				}
			}
		})
	}
}

func writeProbeFile(t *testing.T, dir, name, data string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func removeProbeFile(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.Remove(filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
}

func symlinkProbeFile(t *testing.T, dir, name string) {
	t.Helper()
	removeProbeFile(t, dir, name)
	if err := os.Symlink("cgroup.type", filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareSlotProbeControlsReadyJournal(t *testing.T) {
	for _, valid := range []bool{true, false} {
		t.Run(map[bool]string{true: "valid", false: "populated"}[valid], func(t *testing.T) {
			_, groupPath, baseFD, groupFD, slot, owner := lifecycleFixture(t)
			path := filepath.Join(groupPath, slotName(slot.UID, slot.Index))
			probe := func(fd int, timeout time.Duration) error {
				writeProbeFixture(t, path)
				if !valid {
					writeProbeFile(t, path, "cgroup.events", "populated 1\n")
				}
				return probeCgroupCleanup(fd, timeout)
			}
			j, cg, err := prepareSlot(baseFD, groupFD, slot, "test-identity", owner, probe)
			if (err == nil) != valid {
				t.Fatalf("prepare error = %v", err)
			}
			if cg != nil {
				if err := cg.Close(); err != nil {
					t.Fatal(err)
				}
			}
			stored, exists, err := readJournal(baseFD, slot, owner)
			if err != nil || !exists {
				t.Fatalf("read journal: exists=%t err=%v", exists, err)
			}
			want := "preparing"
			if valid {
				want = "ready"
			}
			if j.Phase != want || stored.Phase != want {
				t.Fatalf("phase: returned=%q stored=%q", j.Phase, stored.Phase)
			}
			data, err := os.ReadFile(filepath.Join(path, "cgroup.kill"))
			if err != nil || !bytes.Equal(data, []byte("untouched")) {
				t.Fatalf("kill changed: %q, %v", data, err)
			}
			if !valid && recoverSlot(baseFD, groupFD, slot, owner, emptyCgroup) == nil {
				t.Fatal("failed probe slot not quarantined")
			}
			if valid {
				called := false
				failKill := func(int, time.Duration) error { called = true; return errors.New("kill write failed") }
				if err := recoverSlot(baseFD, groupFD, slot, owner, failKill); err == nil || !called {
					t.Fatalf("failed cleanup accepted: called=%t err=%v", called, err)
				}
				remaining, exists, err := readJournal(baseFD, slot, owner)
				if err != nil || !exists || remaining.Phase != "ready" {
					t.Fatalf("failed cleanup lost quarantine journal: exists=%t journal=%+v err=%v", exists, remaining, err)
				}
				if _, err := os.Stat(path); err != nil {
					t.Fatalf("failed cleanup removed cgroup: %v", err)
				}
			}
		})
	}
}
