//go:build linux

package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Gobd/syd-guard/internal/session"
	"golang.org/x/sys/unix"
)

type watchdog struct {
	guard   *os.File
	cmd     *exec.Cmd
	done    chan error
	crashed bool
	live    bool
}

// startWatchdog executes only this fixed immutable binary. Its socket peer and
// the locked slot FD authenticate the otherwise inaccessible watchdog mode.
func startWatchdog(slot *launchSlot, j slotJournal) (*watchdog, error) {
	return startWatchdogMode(slot, j, false)
}

// startWatchdogMode uses only the fixed immutable helper and its existing
// authenticated parent/slot/journal handshake; live remains unactivated.
func startWatchdogMode(slot *launchSlot, j slotJournal, live bool) (*watchdog, error) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	parent := os.NewFile(uintptr(pair[0]), "watchdog-parent")
	child := os.NewFile(uintptr(pair[1]), "watchdog-child")
	mode := "--watchdog"
	if live {
		mode = "--watchdog-live"
	}
	cmd := exec.Command(executable, mode)
	// Keep the privileged watchdog out of the sudo/terminal signal group; the
	// pidfd and cgroup, not this session boundary, provide lifecycle control.
	// Clone the launcher's already-private namespace before any binds. The
	// watchdog must not retain or attempt to remove mounted targets after the
	// launcher dies; it needs an independent, unmounted recovery view.
	cmd.SysProcAttr = watchdogProcessAttributes()
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.Stdin = nil
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{child, slot.File}
	if err := cmd.Start(); err != nil {
		_ = parent.Close()
		_ = child.Close()
		return nil, err
	}
	_ = child.Close()
	watch := &watchdog{guard: parent, cmd: cmd, done: make(chan error, 1), live: live}
	go func() { watch.done <- cmd.Wait() }()
	if err := parent.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		_ = parent.Close()
		return nil, err
	}
	if _, err := fmt.Fprintf(parent, "%d:%d:%s\n", slot.UID, slot.Index, j.Nonce); err != nil {
		_ = parent.Close()
		return nil, err
	}
	var ack [1]byte
	if _, err := io.ReadFull(parent, ack[:]); err != nil || ack[0] != 'R' {
		_ = parent.Close()
		return nil, errors.New("watchdog failed to authenticate or start")
	}
	if err := parent.SetDeadline(time.Time{}); err != nil {
		_ = parent.Close()
		return nil, err
	}
	return watch, nil
}

func watchdogProcessAttributes() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true, Cloneflags: unix.CLONE_NEWNS}
}

// finish requests subtree kill/recovery, then waits for watchdog completion.
// EOF has the same effect when the privileged parent dies unexpectedly.
func (w *watchdog) finish() error {
	return w.finishWithRequest(func() error {
		_, err := w.guard.Write([]byte{'X'})
		return err
	})
}

// finishLive obtains the same cleanup receipt as the non-live protocol. A
// missing receipt or watchdog failure keeps the slot held or quarantined.
func (w *watchdog) finishLive(client *liveWatchClient) error {
	if client == nil || client.fd != int(w.guard.Fd()) {
		return errors.New("invalid live watchdog client")
	}
	return w.finishWithRequest(func() error {
		now, err := monotonicNanoseconds()
		if err != nil {
			return err
		}
		if now > ^uint64(0)-uint64(10*time.Second) {
			return errors.New("watchdog clock overflow")
		}
		return client.stop(now + uint64(10*time.Second))
	})
}

func (w *watchdog) finishWithRequest(send func() error) error {
	if w.crashed {
		_ = w.guard.Close()
		return errors.New("watchdog exited unexpectedly")
	}
	defer func() { _ = w.guard.Close() }()
	if err := w.guard.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	if err := send(); err != nil {
		select {
		case waitErr := <-w.done:
			w.crashed = true
			return errors.Join(err, waitErr)
		default:
		}
		return err
	}
	var ack [1]byte
	_, readErr := io.ReadFull(w.guard, ack[:])
	if readErr != nil {
		select {
		case waitErr := <-w.done:
			w.crashed = true
			return errors.Join(errors.New("watchdog cleanup failed; slot remains quarantined"), waitErr)
		default:
		}
		return errors.New("watchdog cleanup uncertain; slot remains held or quarantined")
	}
	select {
	case waitErr := <-w.done:
		w.crashed = true // Reaped: safe for parent to reconcile on failure.
		if ack[0] != 'C' || waitErr != nil {
			return errors.New("watchdog cleanup failed; slot remains quarantined")
		}
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("watchdog did not exit; slot remains held")
	}
}

func watchdogMain() error { return watchdogMainMode(false) }

// A future live-only launch may call this fixed mode after all startup gates.
// No CLI or privileged dispatcher currently enables it.
func watchdogMainMode(live bool) error {
	if os.Geteuid() != 0 || os.Getuid() != 0 {
		return errors.New("watchdog requires root")
	}
	if err := verifyInstallation(); err != nil {
		return err
	}
	typeValue, err := unix.GetsockoptInt(3, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || typeValue != unix.SOCK_STREAM {
		return errors.New("invalid watchdog socket")
	}
	domain, err := unix.GetsockoptInt(3, unix.SOL_SOCKET, unix.SO_DOMAIN)
	if err != nil || domain != unix.AF_UNIX {
		return errors.New("invalid watchdog socket domain")
	}
	peer, err := unix.GetsockoptUcred(3, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil || peer.Uid != 0 || int(peer.Pid) != os.Getppid() || peer.Pid <= 0 {
		return errors.New("watchdog parent is not authenticated")
	}
	parentFD, err := unix.PidfdOpen(int(peer.Pid), 0)
	if err != nil {
		return fmt.Errorf("watchdog parent pidfd unavailable: %w", err)
	}
	defer func() { _ = unix.Close(parentFD) }()
	parentIdentity, err := session.ProcessIdentity(int(peer.Pid))
	if err != nil {
		return err
	}
	trusted, err := trustedPath(executable, true)
	if err != nil {
		return err
	}
	var parentExecutable unix.Stat_t
	if err := unix.Stat("/proc/"+strconv.Itoa(int(peer.Pid))+"/exe", &parentExecutable); err != nil || parentExecutable.Dev != trusted.Dev || parentExecutable.Ino != trusted.Ino {
		return errors.New("watchdog parent executable mismatch")
	}
	guard := os.NewFile(3, "watchdog-guard")
	defer func() { _ = guard.Close() }()
	if err := guard.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	line, err := bufio.NewReader(io.LimitReader(guard, 256)).ReadString('\n')
	if err != nil {
		return errors.New("invalid watchdog handshake")
	}
	parts := strings.Split(strings.TrimSuffix(line, "\n"), ":")
	if len(parts) != 3 {
		return errors.New("invalid watchdog selection")
	}
	uid64, err := strconv.ParseUint(parts[0], 10, 31)
	if err != nil || uid64 == 0 {
		return errors.New("invalid watchdog UID")
	}
	index, err := strconv.Atoi(parts[1])
	if err != nil || index < 0 || index >= launchSlotsPerUID {
		return errors.New("invalid watchdog slot")
	}
	nonce, err := hex.DecodeString(parts[2])
	if err != nil || len(nonce) != 32 || hex.EncodeToString(nonce) != parts[2] {
		return errors.New("invalid watchdog nonce")
	}
	baseFD, err := unix.Open(anchorBase, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(baseFD) }()
	groupFD, err := openCgroupBase()
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(groupFD) }()
	slot := &launchSlot{File: os.NewFile(4, "watchdog-slot"), UID: uint32(uid64), Index: index}
	defer func() { _ = slot.Close() }()
	var held, named unix.Stat_t
	if err := unix.Fstat(4, &held); err != nil {
		return err
	}
	if err := unix.Fstatat(baseFD, slotName(slot.UID, slot.Index), &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if held.Dev != named.Dev || held.Ino != named.Ino || held.Uid != 0 || held.Mode&unix.S_IFMT != unix.S_IFREG || held.Mode&0o7777 != 0o600 || held.Nlink != 1 {
		return errors.New("invalid watchdog slot descriptor")
	}
	if err := unix.Flock(4, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.New("watchdog slot lock not held")
	}
	j, exists, err := readJournal(baseFD, slot, 0)
	if err != nil || !exists || j.Phase != "ready" || j.Nonce != parts[2] || j.ParentPID != int(peer.Pid) || j.ParentIdentity != parentIdentity {
		return errors.New("watchdog journal binding mismatch")
	}
	if _, err := guard.Write([]byte{'R'}); err != nil {
		return err
	}
	if err := guard.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	// pidfd detects parent death even if a fork-in-progress briefly inherited
	// the guard FD before its close-on-exec transition.
	var cleanupStart, cleanupEnd, killStart, killEnd time.Time
	var killErr, cleanupErr error
	cleanup := func() error {
		cleanupStart = time.Now()
		cleanupErr = watchdogCleanup(baseFD, groupFD, slot, j, 0, func(fd int, timeout time.Duration) error {
			killStart = time.Now()
			killErr = killCgroup(fd, timeout)
			killEnd = time.Now()
			return killErr
		})
		cleanupEnd = time.Now()
		return nil // Preserve the protocol and cleanup outcomes separately.
	}
	var event watchdogEvent
	var waitErr error
	if live {
		event, waitErr = serveLiveWatchdog(parentFD, 3, j.Nonce, defaultLiveWatchOps(), cleanup)
	} else {
		event, waitErr = waitWatchdogEvent(parentFD, 3)
		if waitErr != nil {
			return waitErr
		}
		_ = cleanup()
	}
	ackOK := false
	if cleanupErr == nil {
		// If the parent crashed this write may fail; cleanup has already completed.
		if live {
			_ = guard.SetWriteDeadline(time.Now().Add(time.Second))
		}
		_, err := guard.Write([]byte{'C'})
		ackOK = err == nil
	}
	// Never emit diagnostics until the kill, cleanup and acknowledgement have
	// been attempted; a blocked output pipe cannot delay the safety operation.
	diagnostic(fmt.Sprintf("watchdog event_time=%s poll_count=%d pidfd_revents=%#x socket_revents=%#x cleanup_start=%s cleanup_end=%s cleanup_ok=%t kill_called=%t kill_start=%s kill_end=%s kill_ok=%t ack_ok=%t", event.at.Format(time.RFC3339Nano), event.count, uint16(event.pidfdRevents), uint16(event.socketRevents), cleanupStart.Format(time.RFC3339Nano), cleanupEnd.Format(time.RFC3339Nano), cleanupErr == nil, !killStart.IsZero(), killStart.Format(time.RFC3339Nano), killEnd.Format(time.RFC3339Nano), !killStart.IsZero() && killErr == nil, ackOK))
	return errors.Join(waitErr, cleanupErr)
}

// watchdogCleanup rereads the durable journal: the parent's initial copy can
// predate a later resource transaction. If rereading fails, kill only the
// originally pinned cgroup and quarantine everything else.
func watchdogCleanup(baseFD, groupFD int, slot *launchSlot, initial slotJournal, owner uint32, kill func(int, time.Duration) error) error {
	current, exists, err := readJournal(baseFD, slot, owner)
	if err == nil && exists && current.Nonce == initial.Nonce && current.ParentPID == initial.ParentPID && current.ParentIdentity == initial.ParentIdentity && current.AnchorDev == initial.AnchorDev && current.AnchorIno == initial.AnchorIno && current.CgroupDev == initial.CgroupDev && current.CgroupIno == initial.CgroupIno {
		return cleanupSlot(baseFD, groupFD, slot, current, owner, kill)
	}
	fd, openErr := openCheckedDirectory(groupFD, slotName(slot.UID, slot.Index), initial.CgroupDev, initial.CgroupIno, owner)
	if openErr != nil {
		return errors.Join(errors.New("watchdog journal changed; slot quarantined"), err, openErr)
	}
	killErr := kill(fd, 5*time.Second)
	_ = unix.Close(fd)
	return errors.Join(errors.New("watchdog journal changed; slot quarantined"), err, killErr)
}

type watchdogEvent struct {
	at                          time.Time
	count                       int
	pidfdRevents, socketRevents int16
}

func waitWatchdogEvent(parentFD, socketFD int) (watchdogEvent, error) {
	//nolint:gosec // Linux file descriptors are nonnegative signed 32-bit values
	fds := []unix.PollFd{{Fd: int32(parentFD), Events: unix.POLLIN}, {Fd: int32(socketFD), Events: unix.POLLIN | unix.POLLHUP}}
	for {
		n, err := unix.Poll(fds, -1)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return watchdogEvent{}, err
		}
		if fds[0].Revents != 0 || fds[1].Revents != 0 {
			return watchdogEvent{at: time.Now(), count: n, pidfdRevents: fds[0].Revents, socketRevents: fds[1].Revents}, nil
		}
	}
}
