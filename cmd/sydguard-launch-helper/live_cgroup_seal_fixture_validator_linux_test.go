//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLiveSealFixtureDigestValidation(t *testing.T) {
	for _, bad := range []string{"", strings.Repeat("0", 63), strings.Repeat("a", 63) + "G", strings.Repeat("A", 64), strings.Repeat("0", 65), strings.Repeat("0", 64) + "\n"} {
		if _, err := fixtureDigest(bad); err == nil {
			t.Fatalf("accepted malformed digest %q", bad)
		}
	}
	if _, err := fixtureDigest(strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
}
func TestLiveSealFixtureEnvironmentValidation(t *testing.T) {
	for _, tc := range []struct{ child, opt, digest string }{
		{"yes", "", ""}, {"", "yes", ""}, {"", "1", ""}, {"1", "1", strings.Repeat("a", 64)}, {"1", "", strings.Repeat("a", 64)},
	} {
		if _, _, err := fixtureParseMode(tc.child, tc.opt, tc.digest); err == nil {
			t.Fatalf("accepted malformed environment %+v", tc)
		}
	}
	for _, tc := range []struct{ child, opt, digest, want string }{
		{"", "", "", "skip"}, {"1", "", "", "child"}, {"", "1", strings.Repeat("a", 64), "root"},
	} {
		mode, _, err := fixtureParseMode(tc.child, tc.opt, tc.digest)
		if err != nil || mode != tc.want {
			t.Fatalf("mode=%q err=%v", mode, err)
		}
	}
}
func TestLiveSealFixtureMetadataValidation(t *testing.T) {
	good := unix.Stat_t{Dev: 1, Ino: 2, Uid: 0, Nlink: 1, Mode: unix.S_IFREG | 0o500, Size: 10}
	if err := fixtureBinaryStat(good); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*unix.Stat_t){func(s *unix.Stat_t) { s.Uid = 1 }, func(s *unix.Stat_t) { s.Mode = unix.S_IFREG | 0o700 }, func(s *unix.Stat_t) { s.Nlink = 2 }, func(s *unix.Stat_t) { s.Size = 0 }, func(s *unix.Stat_t) { s.Size = liveSealFixtureMaxBinary + 1 }, func(s *unix.Stat_t) { s.Mode = unix.S_IFDIR | 0o500 }} {
		s := good
		change(&s)
		if fixtureBinaryStat(s) == nil {
			t.Fatalf("accepted unsafe metadata %+v", s)
		}
	}
	changed := good
	changed.Ino++
	if fixtureSameIdentity(good, changed) {
		t.Fatal("accepted replacement binary")
	}
	dir := unix.Stat_t{Dev: 3, Ino: 4, Uid: 0, Mode: unix.S_IFDIR | 0o755, Nlink: 2}
	if fixtureDirectoryStat(dir) != nil {
		t.Fatal("valid fixture directory rejected")
	}
	replaced := dir
	replaced.Ino++
	if fixtureSameDirectory(dir, replaced) {
		t.Fatal("accepted replacement cgroup")
	}
	retired := dir
	retired.Nlink = 0
	if !fixtureSameDirectory(dir, retired) {
		t.Fatal("retained unlinked directory lost identity")
	}
	dir.Mode = unix.S_IFDIR | 0o777
	if fixtureDirectoryStat(dir) == nil {
		t.Fatal("accepted writable fixture parent")
	}
	lock := unix.Stat_t{Uid: 0, Mode: unix.S_IFREG | 0o600, Nlink: 1}
	if fixtureLockStat(lock) != nil {
		t.Fatal("valid lock rejected")
	}
	lock.Mode = unix.S_IFREG | 0o666
	if fixtureLockStat(lock) == nil {
		t.Fatal("accepted writable lock")
	}
}
func TestLiveSealFixtureDeadlineIsSingleBoundedBudget(t *testing.T) {
	now := time.Unix(100, 0)
	d := newFixtureDeadline(now)
	for _, cap := range []time.Duration{0, -time.Second, liveSealFixtureDuration + time.Second} {
		if _, err := d.remaining(now, cap); err == nil {
			t.Fatalf("accepted cap %v", cap)
		}
	}
	left, err := d.remaining(now.Add(29*time.Second), 5*time.Second)
	if err != nil || left != time.Second {
		t.Fatalf("remaining=%v err=%v", left, err)
	}
	if _, err := d.remaining(now.Add(liveSealFixtureDuration), time.Second); err == nil {
		t.Fatal("accepted expired deadline")
	}
	if _, err := (fixtureDeadline{}).remaining(now, time.Second); err == nil {
		t.Fatal("accepted missing deadline")
	}
	if err := fixtureSpawnBudget(d, now.Add(21*time.Second)); err == nil {
		t.Fatal("spawn without reconciliation budget")
	}
	if err := fixtureSpawnBudget(d, now.Add(20*time.Second)); err != nil {
		t.Fatal(err)
	}
}
func TestLiveSealFixtureCleanupPollAndOfflineErrors(t *testing.T) {
	proof := &fixtureCloneStartError{cause: &os.PathError{Op: "fork/exec", Path: liveSealFixtureBinary, Err: unix.ENOENT}}
	if !fixtureOfflineCloneError(proof) {
		t.Fatal("rejected exact offline clone error")
	}
	for _, err := range []error{
		unix.ENOENT,
		&fixtureCloneStartError{cause: &os.PathError{Op: "open", Path: "/dev/null", Err: unix.ENOENT}},
		&fixtureCloneStartError{cause: fmt.Errorf("wrapped: %w", &os.PathError{Op: "open", Path: "/dev/null", Err: unix.ENOENT})},
		&fixtureCloneStartError{cause: &os.PathError{Op: "fork/exec", Path: "/wrong", Err: unix.ENOENT}},
		&fixtureCloneStartError{cause: &os.PathError{Op: "open", Path: liveSealFixtureBinary, Err: unix.ENOENT}},
		&fixtureCloneStartError{cause: &os.PathError{Op: "fork/exec", Path: liveSealFixtureBinary, Err: unix.EINVAL}},
		errors.Join(proof, errors.New("pipe close failed")),
	} {
		if fixtureOfflineCloneError(err) {
			t.Fatalf("accepted unrelated offline failure %v", err)
		}
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := read.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := write.Close(); err != nil {
		t.Fatal(err)
	}
	d := newFixtureDeadline(time.Now())
	if err := fixturePoll(int(read.Fd()), d, time.Second, false); err != nil {
		t.Fatal(err)
	}
	if err := fixturePoll(int(read.Fd()), d, time.Second, true); err == nil {
		t.Fatal("HUP accepted as positive pidfd exit")
	}
	expired := fixtureDeadline{end: time.Now().Add(-time.Second)}
	if err := fixturePoll(int(read.Fd()), expired, time.Second, false); err == nil {
		t.Fatal("expired cleanup poll succeeded")
	}
}
func TestLiveSealFixtureCloseFailurePropagates(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := read.Close(); err != nil {
		t.Fatal(err)
	}
	if err := fixtureCloseFiles(read, write); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("close failure not propagated: %v", err)
	}
}
func TestLiveSealFixtureWaitAccounting(t *testing.T) {
	c := &fixtureChild{pidfd: 123}
	waitFailure := errors.New("injected OS wait failure")
	err := fixtureAccountWait(c, func() (*os.ProcessState, error) { return nil, waitFailure }, false)
	if !errors.Is(err, waitFailure) || c.reaped || c.pidfd != 123 {
		t.Fatalf("lost unreaped authority: %+v %v", c, err)
	}
	cmd := exec.Command("/bin/sh", "-c", "exit 7")
	exitErr := cmd.Run()
	if exitErr == nil || cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 7 {
		t.Fatalf("ordinary child state: %v", exitErr)
	}
	err = fixtureAccountWait(c, func() (*os.ProcessState, error) { return nil, exitErr }, false)
	if !errors.Is(err, exitErr) || !c.reaped || c.pidfd != 123 {
		t.Fatalf("nonzero exit accounting: %+v %v", c, err)
	}
}
func TestLiveSealFixtureWaitTimeoutRetainsSingleHandle(t *testing.T) {
	wait := make(chan fixtureWaitResult, 1)
	c := &fixtureChild{pidfd: 123, waitResult: wait}
	r := &fixtureRun{deadline: fixtureDeadline{end: time.Now().Add(2 * time.Millisecond)}}
	if err := r.observeWait(c); err == nil || c.reaped || c.pidfd != 123 || !c.waitTimedOut {
		t.Fatalf("wait timeout lost authority: %+v %v", c, err)
	}
	wait <- fixtureWaitResult{err: errors.New("late result")}
	if err := r.observeWait(c); err == nil || c.reaped || c.waitResult != wait || c.waitObserved {
		t.Fatalf("timeout retried or accepted late wait: %+v %v", c, err)
	}
}
func TestLiveSealFixtureDeadlineAwarePidfdLiveness(t *testing.T) {
	now := time.Unix(100, 0)
	d := fixtureDeadline{end: now.Add(time.Second)}
	calls := 0
	err := fixturePidfdAliveWith(7, d, func() time.Time { return now }, func([]unix.PollFd, int) (int, error) {
		calls++
		now = now.Add(400 * time.Millisecond)
		return 0, unix.EINTR
	})
	if err == nil || calls != 3 {
		t.Fatalf("EINTR loop exceeded deadline: calls=%d err=%v", calls, err)
	}
}
func TestLiveSealFixtureMissingPidfdClosesPrivatePipes(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	c := &fixtureChild{pidfd: -1, release: write, ready: read}
	r := &fixtureRun{deadline: newFixtureDeadline(time.Now())}
	if err := r.reconcileWithoutPidfd(c); err == nil || c.reaped || !c.releaseClosed || c.ready != nil || !c.noPidfdHandled {
		t.Fatalf("unsafe missing pidfd accounting: %+v %v", c, err)
	}
}
func TestLiveSealFixtureFreshNames(t *testing.T) {
	a, err := fixtureNewGroupName(5, "clone-wins")
	if err != nil {
		t.Fatal(err)
	}
	b, err := fixtureNewGroupName(5, "clone-wins")
	if err != nil {
		t.Fatal(err)
	}
	if a == b || !strings.HasPrefix(a, "seal-5-") || !strings.HasSuffix(a, "-clone-wins") {
		t.Fatalf("invalid names %q %q", a, b)
	}
	if _, err := fixtureNewGroupName(5, "selected-by-controller"); err == nil {
		t.Fatal("accepted invalid case")
	}
}
func TestLiveSealFixtureMembershipAndCredentialValidators(t *testing.T) {
	path, err := fixtureCgroupPath([]byte("0::/sydguard-live-seal-fixture/seal-4-clone-wins\n"))
	if err != nil || path != "/sydguard-live-seal-fixture/seal-4-clone-wins" {
		t.Fatalf("path=%q err=%v", path, err)
	}
	for _, bad := range []string{"", "0::/foo", "0::/foo/../bar\n", "0::/foo\n0::/bar\n", "1:name:/foo\n"} {
		if _, err := fixtureCgroupPath([]byte(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if err := fixtureRootStatus([]byte("Name:\tfixture\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n")); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"Uid: 0 0 0 0\n", "Uid: 0 0 0 0\nGid: 0 0 1 0\n", "Uid: 0 0 0 0\nUid: 0 0 0 0\nGid: 0 0 0 0\n"} {
		if fixtureRootStatus([]byte(bad)) == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
