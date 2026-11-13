//go:build linux

package main

import (
	"errors"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/Gobd/syd-guard/internal/session"
	"golang.org/x/sys/unix"
)

// networkChild pins a parent-spawned child's lifetime. Socketpair SO_PEERCRED
// cannot authenticate the post-exec child because it describes the creator.
type networkChild struct {
	pid           int
	start         string
	executableDev uint64
	executableIno uint64
	pidfd         int
}

// pinNetworkChild requires the PID and pidfd returned atomically by this
// parent's spawn (SysProcAttr.PidFD), plus an authenticated executable FD.
// It checks the executable after exec, not merely the forked parent image.
func pinNetworkChild(pid, pidfd int, executable *os.File) (*networkChild, error) {
	if pid <= 0 || pidfd < 0 || executable == nil {
		return nil, errors.New("invalid network child")
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(executable.Fd()), &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Ino == 0 {
		return nil, errors.New("invalid immutable executable descriptor")
	}
	fd, err := unix.FcntlInt(uintptr(pidfd), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, err
	}
	if err := verifyPidfdPID(fd, pid); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	child := &networkChild{pid: pid, executableDev: st.Dev, executableIno: st.Ino, pidfd: fd}
	identity, err := session.ProcessIdentity(pid)
	if err == nil {
		child.start = identity
		err = child.verify()
	}
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return child, nil
}

// fdinfo is kernel-provided and the FD number is the helper's own duplicate.
func verifyPidfdPID(fd, pid int) error {
	file, err := os.Open("/proc/self/fdinfo/" + strconv.Itoa(fd))
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(data) > 4096 {
		return errors.New("invalid pidfd metadata")
	}
	seen := false
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "Pid:" {
			if seen || len(fields) != 2 || fields[1] != strconv.Itoa(pid) {
				return errors.New("pidfd child mismatch")
			}
			seen = true
		}
	}
	if !seen {
		return errors.New("missing pidfd child identity")
	}
	return nil
}

func (c *networkChild) verify() error {
	if c == nil || c.pid <= 0 || c.pidfd < 0 || c.start == "" {
		return errors.New("invalid pinned child")
	}
	poll := []unix.PollFd{{Fd: int32(c.pidfd), Events: unix.POLLIN}} //nolint:gosec // kernel file descriptors fit int32
	checkAlive := func() error {
		poll[0].Revents = 0
		n, err := unix.Poll(poll, 0)
		if err != nil || n != 0 || poll[0].Revents != 0 {
			return errors.New("network child exited or pidfd invalid")
		}
		return nil
	}
	if err := checkAlive(); err != nil {
		return err
	}
	identity, err := session.ProcessIdentity(c.pid)
	if err != nil || identity != c.start {
		return errors.New("network child start identity changed")
	}
	var st unix.Stat_t
	if err := unix.Stat("/proc/"+strconv.Itoa(c.pid)+"/exe", &st); err != nil || st.Dev != c.executableDev || st.Ino != c.executableIno {
		return errors.New("network child executable changed")
	}
	return checkAlive()
}

func (c *networkChild) Close() error {
	if c == nil || c.pidfd < 0 {
		return nil
	}
	err := unix.Close(c.pidfd)
	c.pidfd = -1
	return err
}
