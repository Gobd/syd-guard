//go:build linux

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/session"
	"golang.org/x/sys/unix"
)

// Provisioned separately by the parent in a private ROOT VM. The fixture
// does not create or remove its fixed parents or change installed helper paths.
// The executable is outside /run because the VM mounts /run with NOEXEC.
const (
	liveSealFixtureParent          = "/sys/fs/cgroup/sydguard-live-seal-fixture"
	liveSealFixtureStage           = "/run/sydguard-live-seal-fixture"
	liveSealFixtureBinary          = "/usr/local/libexec/.sydguard-live-seal-fixture/fixture.test"
	liveSealFixtureLock            = "fixture.lock"
	liveSealFixtureDuration        = 30 * time.Second
	liveSealFixtureMaxBinary       = 128 * 1024 * 1024
	linuxInitialCgroupNamespaceIno = 0xeffffffb
)

type fixtureDeadline struct{ end time.Time }

func newFixtureDeadline(now time.Time) fixtureDeadline {
	return fixtureDeadline{now.Add(liveSealFixtureDuration)}
}
func (d fixtureDeadline) remaining(now time.Time, cap time.Duration) (time.Duration, error) {
	if cap <= 0 || cap > liveSealFixtureDuration || d.end.IsZero() || !now.Before(d.end) {
		return 0, errors.New("fixture deadline exhausted or invalid cap")
	}
	left := d.end.Sub(now)
	if left > cap {
		left = cap
	}
	return left, nil
}

// Do not start a child if insufficient budget remains for readiness and
// pidfd-based emergency reconciliation. Blocking kernel calls remain unbounded.
func fixtureSpawnBudget(d fixtureDeadline, now time.Time) error {
	left, err := d.remaining(now, liveSealFixtureDuration)
	if err != nil {
		return err
	}
	if left < 10*time.Second {
		return errors.New("insufficient fixture child reconciliation budget")
	}
	return nil
}
func fixturePoll(fd int, d fixtureDeadline, cap time.Duration, requireReadable bool) error {
	if _, err := d.remaining(time.Now(), cap); err != nil {
		return err
	}
	phaseEnd := time.Now().Add(cap)
	if phaseEnd.Before(d.end) {
		d.end = phaseEnd
	}
	for {
		left, err := d.remaining(time.Now(), cap)
		if err != nil {
			return err
		}
		// Ceiling avoids turning a positive sub-millisecond budget into a busy poll.
		ms := int((left + time.Millisecond - 1) / time.Millisecond)
		p := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLHUP}}
		n, err := unix.Poll(p, ms)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("fixture poll timeout")
		}
		if p[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
			return errors.New("fixture poll error")
		}
		if p[0].Revents&unix.POLLIN != 0 || (!requireReadable && p[0].Revents&unix.POLLHUP != 0) {
			_, err := d.remaining(time.Now(), cap)
			return err
		}
		if p[0].Revents&unix.POLLHUP != 0 {
			return errors.New("fixture pidfd did not positively report exit")
		}
	}
}
func fixturePidfdAliveWith(fd int, d fixtureDeadline, now func() time.Time, poll func([]unix.PollFd, int) (int, error)) error {
	for {
		if _, err := d.remaining(now(), liveSealFixtureDuration); err != nil {
			return err
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := poll(fds, 0)
		if _, deadlineErr := d.remaining(now(), liveSealFixtureDuration); deadlineErr != nil {
			return deadlineErr
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n != 0 || fds[0].Revents != 0 {
			return fmt.Errorf("fixture child is not alive: pidfd=%d poll=%d revents=%#x", fd, n, fds[0].Revents)
		}
		return nil
	}
}
func fixturePidfdAlive(fd int, d fixtureDeadline) error {
	return fixturePidfdAliveWith(fd, d, time.Now, unix.Poll)
}
func fixtureDigest(value string) ([32]byte, error) {
	var result [32]byte
	b, err := hex.DecodeString(value)
	if err != nil || len(b) != len(result) || hex.EncodeToString(b) != value {
		return result, errors.New("expected lowercase SHA-256 manifest")
	}
	copy(result[:], b)
	return result, nil
}
func fixtureParseMode(child, opt, digest string) (string, [32]byte, error) {
	var empty [32]byte
	if child == "1" {
		if opt != "" || digest != "" {
			return "", empty, errors.New("invalid fixture child environment")
		}
		return "child", empty, nil
	}
	if child != "" {
		return "", empty, errors.New("invalid fixture child flag")
	}
	if opt == "" {
		return "skip", empty, nil
	}
	if opt != "1" {
		return "", empty, errors.New("invalid fixture root opt-in")
	}
	hash, err := fixtureDigest(digest)
	if err != nil {
		return "", empty, err
	}
	return "root", hash, nil
}

// Owned descriptors are closed once; a close error is reported, never retried.
func fixtureCloseFiles(files ...*os.File) error {
	var err error
	for _, f := range files {
		if f != nil {
			err = errors.Join(err, f.Close())
		}
	}
	return err
}
func fixtureSameIdentity(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Mode == b.Mode && a.Nlink == b.Nlink
}
func fixtureSameDirectory(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Mode == b.Mode
}
func fixtureBinaryStat(s unix.Stat_t) error {
	if s.Uid != 0 || s.Mode&unix.S_IFMT != unix.S_IFREG || s.Mode&0o7777 != 0o500 || s.Nlink != 1 || s.Size <= 0 || s.Size > liveSealFixtureMaxBinary {
		return errors.New("unsafe fixture binary metadata")
	}
	return nil
}
func fixtureDirectoryStat(s unix.Stat_t) error {
	if s.Uid != 0 || s.Mode&unix.S_IFMT != unix.S_IFDIR || s.Mode&0o022 != 0 {
		return errors.New("unsafe fixture directory")
	}
	return nil
}
func fixtureLockStat(s unix.Stat_t) error {
	if s.Uid != 0 || s.Mode&unix.S_IFMT != unix.S_IFREG || s.Mode&0o7777 != 0o600 || s.Nlink != 1 {
		return errors.New("unsafe fixture lock")
	}
	return nil
}

type fixtureBinary struct {
	file   *os.File
	stat   unix.Stat_t
	digest [32]byte
	lock   *fixtureRunLock
}

func (b *fixtureBinary) verify(d fixtureDeadline) error {
	if err := b.lock.verify(); err != nil {
		return err
	}
	if _, err := d.remaining(time.Now(), liveSealFixtureDuration); err != nil {
		return err
	}
	var held, named, running unix.Stat_t
	if err := unix.Fstat(int(b.file.Fd()), &held); err != nil {
		return err
	}
	if err := unix.Lstat(liveSealFixtureBinary, &named); err != nil {
		return err
	}
	if err := unix.Stat("/proc/self/exe", &running); err != nil {
		return err
	}
	if fixtureBinaryStat(held) != nil || fixtureBinaryStat(named) != nil || !fixtureSameIdentity(held, b.stat) || !fixtureSameIdentity(held, named) || !fixtureSameIdentity(held, running) || held.Size != b.stat.Size {
		return errors.New("fixture executable identity changed")
	}
	h := sha256.New()
	reader := io.NewSectionReader(b.file, 0, held.Size)
	buf := make([]byte, 64*1024)
	for {
		if _, err := d.remaining(time.Now(), liveSealFixtureDuration); err != nil {
			return err
		}
		n, err := reader.Read(buf)
		if n > 0 {
			if _, werr := h.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
	}
	if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), hex.EncodeToString(b.digest[:])) {
		return errors.New("fixture executable digest mismatch")
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(b.file.Fd()), &after); err != nil {
		return err
	}
	if !fixtureSameIdentity(held, after) || held.Size != after.Size || held.Mtim != after.Mtim || held.Ctim != after.Ctim {
		return errors.New("fixture executable changed while hashing")
	}
	if err := b.lock.verify(); err != nil {
		return err
	}
	_, err := d.remaining(time.Now(), liveSealFixtureDuration)
	return err
}
func fixtureOpenBinary(d fixtureDeadline, digest [32]byte, lock *fixtureRunLock) (*fixtureBinary, error) {
	trusted, err := trustedPath(liveSealFixtureBinary, true)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open(liveSealFixtureBinary, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "fixture-executable")
	b := &fixtureBinary{file: f, stat: trusted, digest: digest, lock: lock}
	if err := b.verify(d); err != nil {
		return nil, errors.Join(err, fixtureCloseFiles(f))
	}
	return b, nil
}

type fixtureRunLock struct {
	file                *os.File
	dir                 *os.File
	stageStat, lockStat unix.Stat_t
}

func (l *fixtureRunLock) verify() error {
	var heldStage, namedStage, heldLock, namedLock unix.Stat_t
	if err := unix.Fstat(int(l.dir.Fd()), &heldStage); err != nil {
		return err
	}
	if err := unix.Lstat(liveSealFixtureStage, &namedStage); err != nil {
		return err
	}
	if err := unix.Fstat(int(l.file.Fd()), &heldLock); err != nil {
		return err
	}
	if err := unix.Fstatat(int(l.dir.Fd()), liveSealFixtureLock, &namedLock, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if fixtureDirectoryStat(heldStage) != nil || heldStage.Mode&0o7777 != 0o700 || !fixtureSameDirectory(heldStage, l.stageStat) || !fixtureSameDirectory(heldStage, namedStage) || fixtureLockStat(heldLock) != nil || !fixtureSameIdentity(heldLock, l.lockStat) || !fixtureSameIdentity(heldLock, namedLock) {
		return errors.New("fixture lock or stage identity changed")
	}
	return nil
}
func (l *fixtureRunLock) Close() error { return errors.Join(l.file.Close(), l.dir.Close()) }

// The lock is opened afresh, so it has an independent open-file description;
// flock is not treated as a conflicting lock between inherited descriptions.
func fixtureAcquireLock() (*fixtureRunLock, error) {
	trusted, err := trustedPath(liveSealFixtureStage, false)
	if err != nil {
		return nil, err
	}
	if fixtureDirectoryStat(trusted) != nil || trusted.Mode&0o7777 != 0o700 {
		return nil, errors.New("fixture stage must be ROOT 0700")
	}
	dir, err := unix.Open(liveSealFixtureStage, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	stage := os.NewFile(uintptr(dir), "fixture-stage")
	var held unix.Stat_t
	if err := unix.Fstat(dir, &held); err != nil || !fixtureSameDirectory(trusted, held) {
		return nil, errors.Join(errors.New("fixture stage identity changed"), err, fixtureCloseFiles(stage))
	}
	fd, err := unix.Openat(dir, liveSealFixtureLock, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.Join(err, fixtureCloseFiles(stage))
	}
	f := os.NewFile(uintptr(fd), "fixture-exclusive-lock")
	var named unix.Stat_t
	if err := unix.Fstat(fd, &held); err != nil {
		return nil, errors.Join(err, fixtureCloseFiles(f, stage))
	}
	if err := unix.Fstatat(dir, liveSealFixtureLock, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, errors.Join(err, fixtureCloseFiles(f, stage))
	}
	if fixtureLockStat(held) != nil || !fixtureSameIdentity(held, named) {
		return nil, errors.Join(errors.New("fixture lock identity changed"), fixtureCloseFiles(f, stage))
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, errors.Join(err, fixtureCloseFiles(f, stage))
	}
	lock := &fixtureRunLock{file: f, dir: stage, stageStat: trusted, lockStat: held}
	if err := lock.verify(); err != nil {
		return nil, errors.Join(err, lock.Close())
	}
	return lock, nil
}

type fixtureGroup struct {
	parent     int
	parentStat unix.Stat_t
	fd         int
	name       string
	stat       unix.Stat_t
	removed    bool
	lock       *fixtureRunLock
}

func fixtureCheckParent(fd int, expected unix.Stat_t) error {
	var held, named unix.Stat_t
	var fs unix.Statfs_t
	if err := unix.Fstat(fd, &held); err != nil {
		return err
	}
	if err := unix.Lstat(liveSealFixtureParent, &named); err != nil {
		return err
	}
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return err
	}
	if fixtureDirectoryStat(held) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC || !fixtureSameDirectory(held, expected) || !fixtureSameDirectory(held, named) {
		return errors.New("fixture cgroup parent identity changed")
	}
	return nil
}
func (g *fixtureGroup) checkHeld() error {
	if err := g.lock.verify(); err != nil {
		return err
	}
	if err := fixtureCheckParent(g.parent, g.parentStat); err != nil {
		return err
	}
	var held unix.Stat_t
	var fs unix.Statfs_t
	if err := unix.Fstat(g.fd, &held); err != nil {
		return err
	}
	if err := unix.Fstatfs(g.fd, &fs); err != nil {
		return err
	}
	if fixtureDirectoryStat(held) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC || !fixtureSameDirectory(held, g.stat) {
		return errors.New("fixture held cgroup identity changed")
	}
	return nil
}
func (g *fixtureGroup) checkNamed() error {
	if err := g.checkHeld(); err != nil {
		return err
	}
	var named unix.Stat_t
	if err := unix.Fstatat(g.parent, g.name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if fixtureDirectoryStat(named) != nil || !fixtureSameDirectory(named, g.stat) {
		return errors.New("fixture named cgroup identity changed")
	}
	return nil
}
func fixtureNewGroup(parent int, parentStat unix.Stat_t, name string, lock *fixtureRunLock) (*fixtureGroup, error) {
	if err := lock.verify(); err != nil {
		return nil, err
	}
	if err := fixtureCheckParent(parent, parentStat); err != nil {
		return nil, err
	}
	if err := unix.Mkdirat(parent, name, 0o755); err != nil {
		return nil, err
	} // exclusive; never adopt
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	g := &fixtureGroup{parent: parent, parentStat: parentStat, fd: fd, name: name, lock: lock}
	if err := unix.Fstat(fd, &g.stat); err != nil {
		return nil, errors.Join(err, unix.Close(fd))
	}
	if err := g.checkNamed(); err != nil {
		return nil, errors.Join(err, unix.Close(fd))
	}
	return g, nil
}
func (g *fixtureGroup) remove() error {
	if g.removed {
		return errors.New("fixture cgroup already removed")
	}
	if err := g.checkNamed(); err != nil {
		return err
	}
	if err := unix.Unlinkat(g.parent, g.name, unix.AT_REMOVEDIR); err != nil {
		return err
	}
	g.removed = true
	return nil
}

func fixtureCgroupPath(data []byte) (string, error) {
	if len(data) > 4096 || !strings.HasPrefix(string(data), "0::/") || !strings.HasSuffix(string(data), "\n") || strings.Count(string(data), "\n") != 1 {
		return "", errors.New("invalid cgroup membership")
	}
	p := strings.TrimSuffix(strings.TrimPrefix(string(data), "0::"), "\n")
	if filepath.Clean(p) != p {
		return "", errors.New("unclean cgroup membership")
	}
	return p, nil
}
func fixtureRootStatus(data []byte) error {
	if len(data) > 65536 {
		return errors.New("fixture child status oversized")
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || (f[0] != "Uid:" && f[0] != "Gid:") {
			continue
		}
		if seen[f[0]] || len(f) != 5 {
			return errors.New("invalid fixture child credentials")
		}
		seen[f[0]] = true
		for _, id := range f[1:] {
			if id != "0" {
				return errors.New("fixture child is not ROOT 0/0")
			}
		}
	}
	if !seen["Uid:"] || !seen["Gid:"] {
		return errors.New("missing fixture child credentials")
	}
	return nil
}
func fixtureInitialCgroupNamespace() error {
	var self, init unix.Stat_t
	if err := unix.Stat("/proc/self/ns/cgroup", &self); err != nil {
		return err
	}
	if err := unix.Stat("/proc/1/ns/cgroup", &init); err != nil {
		return err
	}
	if self.Dev != init.Dev || self.Ino != init.Ino || self.Ino != linuxInitialCgroupNamespaceIno {
		return errors.New("fixture requires initial host cgroup namespace")
	}
	return nil
}

// Only this error represents a clone/exec attempt after all preflight checks.
// A failed validation must never be mistaken for offline-cgroup ENOENT.
type fixtureCloneStartError struct{ cause error }

func (e *fixtureCloneStartError) Error() string { return e.cause.Error() }
func (e *fixtureCloneStartError) Unwrap() error { return e.cause }
func fixtureOfflineCloneError(err error) bool {
	// A joined close/validation error must never be accepted as proof.
	startErr, ok := err.(*fixtureCloneStartError)
	if !ok {
		return false
	}
	var pathErr *os.PathError
	return errors.As(startErr.cause, &pathErr) && pathErr.Op == "fork/exec" && pathErr.Path == liveSealFixtureBinary && errors.Is(pathErr.Err, unix.ENOENT)
}

type fixtureWaitResult struct {
	state *os.ProcessState
	err   error
}
type fixtureChild struct {
	cmd            *exec.Cmd
	pidfd          int
	release, ready *os.File
	start          string
	reaped         bool
	releaseClosed  bool
	membership     bool
	group          *fixtureGroup
	noPidfdHandled bool
	waitResult     chan fixtureWaitResult
	waitObserved   bool
	waitTimedOut   bool
	waitRecord     fixtureWaitResult
	waitForced     bool
}
type fixtureRun struct {
	deadline fixtureDeadline
	binary   *fixtureBinary
	children []*fixtureChild
}

func (r *fixtureRun) attempt(g *fixtureGroup) (*fixtureChild, error) {
	if err := g.checkHeld(); err != nil {
		return nil, err
	}
	if err := r.binary.verify(r.deadline); err != nil {
		return nil, err
	}
	if err := fixtureSpawnBudget(r.deadline, time.Now()); err != nil {
		return nil, err
	}
	read, write, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		return nil, errors.Join(err, fixtureCloseFiles(read, write))
	}
	pidfd := -1
	cmd := exec.Command(liveSealFixtureBinary, "-test.run=^TestLiveCgroupSealKernelFixture$")
	cmd.Env = []string{"SYDGUARD_LIVE_SEAL_FIXTURE_CHILD=1"}
	// This controlled ROOT fixture inherits only the parent's standard log
	// streams in addition to its two private pipes. Preserve early test errors
	// without output-draining goroutines or another authority descriptor.
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{read, readyWrite}
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: g.fd, PidFD: &pidfd}
	if err := fixtureSpawnBudget(r.deadline, time.Now()); err != nil {
		return nil, errors.Join(err, fixtureCloseFiles(read, write, readyRead, readyWrite))
	}
	err = cmd.Start()
	var c *fixtureChild
	if err == nil {
		// Retain the child and exact group before closing any post-start pipe.
		c = &fixtureChild{cmd: cmd, pidfd: pidfd, release: write, ready: readyRead, group: g}
		r.children = append(r.children, c)
	}
	closeErr := fixtureCloseFiles(read, readyWrite)
	if err != nil {
		closeErr = errors.Join(closeErr, fixtureCloseFiles(write, readyRead))
		verifyErr := r.binary.verify(r.deadline)
		if closeErr != nil || verifyErr != nil {
			return nil, errors.Join(fmt.Errorf("fixture failed spawn: %w", err), closeErr, verifyErr)
		}
		return nil, &fixtureCloneStartError{cause: err}
	}
	if closeErr != nil {
		return c, fmt.Errorf("fixture post-start pipe close: %w", closeErr)
	}
	if pidfd < 0 {
		return c, errors.New("atomic pidfd missing")
	}
	if err := r.binary.verify(r.deadline); err != nil {
		return c, err
	}
	c.start, err = session.ProcessIdentity(cmd.Process.Pid)
	if err != nil {
		return c, err
	}
	return c, nil
}
func (r *fixtureRun) verifyChild(c *fixtureChild, g *fixtureGroup) error {
	if _, err := r.deadline.remaining(time.Now(), liveSealFixtureDuration); err != nil {
		return err
	}
	if err := g.checkNamed(); err != nil {
		return err
	}
	if err := fixturePidfdAlive(c.pidfd, r.deadline); err != nil {
		return err
	}
	id, err := session.ProcessIdentity(c.cmd.Process.Pid)
	if err != nil || id != c.start {
		return errors.New("fixture child start identity changed")
	}
	base := "/proc/" + strconv.Itoa(c.cmd.Process.Pid)
	status, err := os.ReadFile(base + "/status")
	if err != nil {
		return err
	}
	if err := fixtureRootStatus(status); err != nil {
		return err
	}
	data, err := os.ReadFile(base + "/cgroup")
	if err != nil {
		return err
	}
	p, err := fixtureCgroupPath(data)
	if err != nil || p != "/sydguard-live-seal-fixture/"+g.name {
		return errors.New("fixture child cgroup mismatch")
	}
	var exe unix.Stat_t
	if err := unix.Stat(base+"/exe", &exe); err != nil {
		return err
	}
	if !fixtureSameIdentity(exe, r.binary.stat) {
		return errors.New("fixture child executable mismatch")
	}
	if err := r.binary.verify(r.deadline); err != nil {
		return err
	}
	if err := g.checkNamed(); err != nil {
		return err
	}
	id, err = session.ProcessIdentity(c.cmd.Process.Pid)
	if err != nil || id != c.start {
		return errors.New("fixture child identity changed")
	}
	return fixturePidfdAlive(c.pidfd, r.deadline)
}
func (r *fixtureRun) readyChild(c *fixtureChild, g *fixtureGroup) error {
	if err := r.verifyChild(c, g); err != nil {
		return err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	if _, err := r.deadline.remaining(time.Now(), liveSealFixtureDuration); err != nil {
		return err
	}
	n, err := c.release.Write(nonce[:])
	if err != nil || n != len(nonce) {
		return errors.New("fixture challenge write failed")
	}
	if err := fixturePoll(int(c.ready.Fd()), r.deadline, 5*time.Second, false); err != nil {
		return err
	}
	var answer [33]byte
	n, err = c.ready.Read(answer[:])
	if err != nil || n != len(answer) || answer[0] != 'R' || string(answer[1:]) != string(nonce[:]) {
		return errors.New("fixture challenge mismatch")
	}
	if err := r.verifyChild(c, g); err != nil {
		return err
	}
	c.membership = true
	return nil
}

// A pidfd exit notification is not a reaping receipt. Retain the pidfd and
// unreaped state if Wait returns no ProcessState, even when Wait returns error.
func fixtureAccountWait(c *fixtureChild, wait func() (*os.ProcessState, error), force bool) error {
	state, err := wait()
	if state == nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			state = exit.ProcessState
		}
	}
	if state == nil {
		return errors.Join(errors.New("fixture child wait unproven; unreaped"), err)
	}
	c.reaped = true
	if err != nil && force {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ProcessState == state {
			status, ok := exit.Sys().(syscall.WaitStatus)
			if ok && status.Signaled() && status.Signal() == syscall.SIGKILL {
				err = nil
			}
		}
	}
	if err != nil {
		return fmt.Errorf("fixture child wait: %w", err)
	}
	return nil
}

func (c *fixtureChild) closePipes() error {
	var err error
	if c.release != nil && !c.releaseClosed {
		err = c.release.Close()
		c.releaseClosed = true
	}
	if c.ready != nil {
		err = errors.Join(err, c.ready.Close())
		c.ready = nil
	}
	return err
}

// No PID-based fallback: contain an anomalous child through its original
// checked cgroup, but never treat drain as a wait/reaping receipt.
func (r *fixtureRun) reconcileWithoutPidfd(c *fixtureChild) error {
	unproven := errors.New("missing atomic pidfd; child reaping unproven")
	if c.noPidfdHandled {
		return unproven
	}
	c.noPidfdHandled = true
	closeErr := c.closePipes()
	if c.group == nil {
		return errors.Join(unproven, closeErr, errors.New("missing original fixture cgroup"))
	}
	if err := c.group.checkNamed(); err != nil {
		return errors.Join(unproven, closeErr, err)
	}
	if _, err := r.deadline.remaining(time.Now(), liveSealFixtureDuration); err != nil {
		return errors.Join(unproven, closeErr, err)
	}
	if err := liveCgroupKill(c.group.fd); err != nil {
		return errors.Join(unproven, closeErr, err)
	}
	if _, err := r.deadline.remaining(time.Now(), 2*time.Second); err != nil {
		return errors.Join(unproven, closeErr, err)
	}
	drainDeadline := time.Now().Add(2 * time.Second)
	if r.deadline.end.Before(drainDeadline) {
		drainDeadline = r.deadline.end
	}
	return errors.Join(unproven, closeErr, liveCgroupDrain(c.group.fd, drainDeadline))
}

// A single owned waiter per child starts only after positive pidfd exit. The
// deadline bounds observation, not the kernel/Go Wait internals. On timeout the
// buffered handle and pidfd stay with the unreaped child; never start a second.
func (r *fixtureRun) observeWait(c *fixtureChild) error {
	if c.waitTimedOut {
		return errors.New("fixture Wait deadline; unreaped quarantine")
	}
	if !c.waitObserved {
		left, err := r.deadline.remaining(time.Now(), liveSealFixtureDuration)
		if err != nil {
			c.waitTimedOut = true
			return errors.Join(err, c.closePipes())
		}
		timer := time.NewTimer(left)
		defer timer.Stop()
		select {
		case c.waitRecord = <-c.waitResult:
			c.waitObserved = true
			if _, err := r.deadline.remaining(time.Now(), liveSealFixtureDuration); err != nil {
				c.waitTimedOut = true
				return errors.Join(err, c.closePipes())
			}
		case <-timer.C:
			c.waitTimedOut = true
			return errors.Join(errors.New("fixture Wait deadline; unreaped quarantine"), c.closePipes())
		}
	}
	err := fixtureAccountWait(c, func() (*os.ProcessState, error) { return c.waitRecord.state, c.waitRecord.err }, c.waitForced)
	err = errors.Join(err, c.closePipes())
	if !c.reaped {
		return err
	}
	fd := c.pidfd
	c.pidfd = -1
	return errors.Join(err, unix.Close(fd))
}
func (r *fixtureRun) reap(c *fixtureChild, force bool) error {
	if c.reaped {
		return nil
	}
	if c.waitResult != nil {
		return r.observeWait(c)
	}
	if c.pidfd < 0 {
		return r.reconcileWithoutPidfd(c)
	}
	if force {
		if err := unix.PidfdSendSignal(c.pidfd, unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
			return errors.Join(fmt.Errorf("fixture pidfd kill: %w", err), c.closePipes())
		}
	} else if !c.releaseClosed {
		err := c.release.Close()
		c.releaseClosed = true
		if err != nil {
			return errors.Join(err, c.closePipes())
		}
	}
	cap := liveSealFixtureDuration
	if !force {
		cap = 3 * time.Second
	}
	if err := fixturePoll(c.pidfd, r.deadline, cap, true); err != nil {
		return errors.Join(fmt.Errorf("fixture child exit: %w", err), c.closePipes())
	}
	// pidfd readiness establishes exit; this is the only Wait goroutine for
	// the directly owned child. An unjoined waiter may live only until the
	// disposable test process exits; it can never yield a clean result later.
	c.waitForced = force
	c.waitResult = make(chan fixtureWaitResult, 1)
	go func(cmd *exec.Cmd, result chan<- fixtureWaitResult) {
		err := cmd.Wait()
		result <- fixtureWaitResult{state: cmd.ProcessState, err: err}
	}(c.cmd, c.waitResult)
	return r.observeWait(c)
}
func (r *fixtureRun) reconcile() error {
	var result error
	for _, c := range r.children {
		if !c.reaped {
			result = errors.Join(result, r.reap(c, true))
		}
	}
	return result
}
func (r *fixtureRun) positive(g *fixtureGroup) error {
	c, err := r.attempt(g)
	if err != nil {
		return err
	}
	if err := r.readyChild(c, g); err != nil {
		return err
	}
	return r.reap(c, false)
}
func (r *fixtureRun) offline(g *fixtureGroup) error {
	c, err := r.attempt(g)
	if err == nil {
		return errors.Join(errors.New("removed original FD accepted a clone; quarantined"), r.reap(c, true))
	}
	if c != nil {
		return errors.Join(errors.New("unexpected child on removed cgroup; quarantined"), err, r.reap(c, true))
	}
	if !fixtureOfflineCloneError(err) {
		return fmt.Errorf("removed original FD returned unrelated error: %w", err)
	}
	return nil
}
func (r *fixtureRun) runCase(parent int, parentStat unix.Stat_t, which, name string) (result error) {
	g, err := fixtureNewGroup(parent, parentStat, name, r.binary.lock)
	if err != nil {
		return err
	}
	groups := []*fixtureGroup{g}
	defer func() {
		// Keep the exact original/replacement FDs live until child reconciliation.
		if result != nil {
			result = errors.Join(result, r.reconcile())
		}
		for i := len(groups) - 1; i >= 0; i-- {
			result = errors.Join(result, unix.Close(groups[i].fd))
		}
	}()
	if err := g.checkNamed(); err != nil {
		return err
	}
	if _, err := r.deadline.remaining(time.Now(), liveSealFixtureDuration); err != nil {
		return err
	}
	if err := liveCgroupKill(g.fd); err != nil {
		return err
	}
	if _, err := r.deadline.remaining(time.Now(), 2*time.Second); err != nil {
		return err
	}
	drainDeadline := time.Now().Add(2 * time.Second)
	if r.deadline.end.Before(drainDeadline) {
		drainDeadline = r.deadline.end
	}
	if err := liveCgroupDrain(g.fd, drainDeadline); err != nil {
		return err
	}
	if which == "clone-wins" {
		c, err := r.attempt(g)
		if err != nil {
			return err
		}
		if err := r.readyChild(c, g); err != nil {
			return err
		}
		if err := g.checkNamed(); err != nil {
			return err
		}
		if _, err := r.deadline.remaining(time.Now(), liveSealFixtureDuration); err != nil {
			return err
		}
		if err := unix.Unlinkat(parent, name, unix.AT_REMOVEDIR); !errors.Is(err, unix.EBUSY) {
			return fmt.Errorf("live clone did not exclude removal: %v", err)
		}
		if err := r.reap(c, false); err != nil {
			return err
		}
	} else if err := r.positive(g); err != nil {
		return err
	}
	if _, err := r.deadline.remaining(time.Now(), liveSealFixtureDuration); err != nil {
		return err
	}
	if err := g.remove(); err != nil {
		return err
	}
	if err := r.offline(g); err != nil {
		return err
	}
	replacement, err := fixtureNewGroup(parent, parentStat, name, r.binary.lock)
	if err != nil {
		return err
	}
	groups = append(groups, replacement)
	if replacement.stat.Dev == g.stat.Dev && replacement.stat.Ino == g.stat.Ino {
		return errors.New("replacement reused original identity")
	}
	if err := r.positive(replacement); err != nil {
		return err
	}
	if err := r.offline(g); err != nil {
		return err
	}
	if _, err := r.deadline.remaining(time.Now(), liveSealFixtureDuration); err != nil {
		return err
	}
	if err := replacement.remove(); err != nil {
		return err
	}
	_, err = r.deadline.remaining(time.Now(), liveSealFixtureDuration)
	return err
}

// Child receives only two private pipes. It checks ROOT, verifies no executable
// FD leaked into its inventory, and answers a fresh per-spawn challenge.
func fixtureChildMain() (result error) {
	if env := os.Environ(); len(env) != 1 || env[0] != "SYDGUARD_LIVE_SEAL_FIXTURE_CHILD=1" {
		return errors.New("unexpected fixture child environment")
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return errors.New("fixture child requires ROOT 0/0")
	}
	defer func() { result = errors.Join(result, unix.Close(3), unix.Close(4)) }()
	var exe unix.Stat_t
	if err := unix.Stat("/proc/self/exe", &exe); err != nil {
		return err
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return err
	}
	if len(entries) > 1024 {
		return errors.New("fixture child FD inventory oversized")
	}
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		var st unix.Stat_t
		if unix.Fstat(fd, &st) == nil && st.Dev == exe.Dev && st.Ino == exe.Ino {
			return errors.New("fixture executable FD leaked into child")
		}
	}
	// One original ten-second child budget covers challenge and release.
	d := fixtureDeadline{end: time.Now().Add(10 * time.Second)}
	if err := fixturePoll(3, d, 10*time.Second, false); err != nil {
		return err
	}
	var nonce [32]byte
	n, err := unix.Read(3, nonce[:])
	if err != nil || n != len(nonce) {
		return errors.New("fixture child challenge failed")
	}
	answer := append([]byte{'R'}, nonce[:]...)
	n, err = unix.Write(4, answer)
	if err != nil || n != len(answer) {
		return errors.New("fixture child reply failed")
	}
	return fixturePoll(3, d, 10*time.Second, false)
}

func fixtureNewGroupName(pid int, which string) (string, error) {
	if pid <= 0 || (which != "clone-wins" && which != "removal-wins") {
		return "", errors.New("invalid fixture case")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("seal-%d-%x-%s", pid, nonce, which), nil
}

func fixtureRunRoot(digest [32]byte) (result error) {
	d := newFixtureDeadline(time.Now())
	lock, err := fixtureAcquireLock()
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, lock.Close()) }()
	if err := fixtureInitialCgroupNamespace(); err != nil {
		return err
	}
	binary, err := fixtureOpenBinary(d, digest, lock)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, binary.file.Close()) }()
	parentStat, err := trustedPath(liveSealFixtureParent, false)
	if err != nil {
		return err
	}
	parent, err := unix.Open(liveSealFixtureParent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, unix.Close(parent)) }()
	if err := fixtureCheckParent(parent, parentStat); err != nil {
		return err
	}
	r := &fixtureRun{deadline: d, binary: binary}
	for _, which := range []string{"clone-wins", "removal-wins"} {
		name, err := fixtureNewGroupName(os.Getpid(), which)
		if err != nil {
			return err
		}
		if err := r.runCase(parent, parentStat, which, name); err != nil {
			return fmt.Errorf("fixture case %s quarantined; preserve %s/%s if present: %w", which, liveSealFixtureParent, name, err)
		}
	}
	return r.reconcile()
}

func TestLiveCgroupSealKernelFixture(t *testing.T) {
	mode, digest, err := fixtureParseMode(os.Getenv("SYDGUARD_LIVE_SEAL_FIXTURE_CHILD"), os.Getenv("SYDGUARD_TEST_LIVE_SEAL_ROOT"), os.Getenv("SYDGUARD_TEST_LIVE_SEAL_SHA256"))
	if err != nil {
		t.Fatal(err)
	}
	if mode == "child" {
		if err := fixtureChildMain(); err != nil {
			t.Fatal(err)
		}
		return
	}
	if mode == "skip" {
		t.Skip("requires separately authorized ROOT VM fixture")
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		t.Fatal("ROOT 0/0 fixture only")
	}
	if err := fixtureRunRoot(digest); err != nil {
		t.Fatal(err)
	}
}
