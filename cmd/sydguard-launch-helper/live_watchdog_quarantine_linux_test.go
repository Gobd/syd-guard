//go:build linux

package main

import (
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLiveWatchRequiresOriginalCgroup(t *testing.T) {
	if _, err := startWatchdogMode(nil, slotJournal{}, true, nil); err == nil {
		t.Fatal("live watch accepted a missing original cgroup")
	}
}

func TestLiveWatchKillOnlyQuarantines(t *testing.T) {
	for _, killErr := range []error{nil, errors.New("kill failed")} {
		calls := 0
		err := quarantineLiveWatchCgroup(42, func(fd int, timeout time.Duration) error {
			calls++
			if fd != 42 || timeout != 5*time.Second {
				t.Fatalf("kill(%d, %v), want original FD and bounded timeout", fd, timeout)
			}
			return killErr
		})
		if calls != 1 || err == nil || (killErr != nil && !errors.Is(err, killErr)) {
			t.Fatalf("calls=%d error=%v, expected quarantine and retained kill error", calls, err)
		}
	}
}

func TestLiveWatchRejectsNonCgroupDescriptor(t *testing.T) {
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	var st unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	slot := &launchSlot{UID: 502, Index: 0}
	if err := checkLiveWatchCgroup(int(dir.Fd()), int(dir.Fd()), slot, slotJournal{CgroupDev: st.Dev, CgroupIno: st.Ino}); err == nil {
		t.Fatal("accepted a non-cgroup descriptor")
	}
}
