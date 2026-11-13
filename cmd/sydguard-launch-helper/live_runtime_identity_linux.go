//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/Gobd/syd-guard/internal/session"
	"golang.org/x/sys/unix"
)

// liveRuntimeIdentity belongs only to ROOT, and is derived from the exact
// trusted child returned by its spawn. Syd normally self-reexecs into a sealed
// memfd, so this pin intentionally differs from the held installed engine inode.
type liveRuntimeIdentity struct {
	pid               int
	start             string
	pidfd, executable *os.File
	dev, ino          uint64
}

func (p *liveRuntimeIdentity) Close() error {
	if p == nil || p.pidfd == nil || p.executable == nil {
		return errors.New("missing runtime authority")
	}
	return errors.Join(p.pidfd.Close(), p.executable.Close())
}
func livePidfdAlive(fd int) error {
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		n, err := unix.Poll(fds, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n != 0 || fds[0].Revents != 0 {
			return errors.New("engine process is not alive")
		}
		return nil
	}
}
func (p *liveRuntimeIdentity) checkProcess() error {
	if p == nil || p.pidfd == nil || p.pid <= 0 {
		return errors.New("missing engine process authority")
	}
	flags, err := unix.FcntlInt(p.pidfd.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		return errors.New("engine pidfd must be CLOEXEC")
	}
	if err := livePidfdAlive(int(p.pidfd.Fd())); err != nil {
		return err
	}
	identity, err := session.ProcessIdentity(p.pid)
	if err != nil || identity != p.start {
		return errors.New("engine process identity changed")
	}
	return livePidfdAlive(int(p.pidfd.Fd()))
}

// openLiveProcExecutable uses only the ROOT-created child PID; user-controlled
// paths or process selectors are never accepted by the launch protocol.
func (p *liveRuntimeIdentity) openExecutable() (*os.File, error) {
	if err := p.checkProcess(); err != nil {
		return nil, err
	}
	fd, err := unix.Open("/proc/"+strconv.Itoa(p.pid)+"/exe", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "live-runtime-executable")
	if err := p.checkProcess(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
func verifyLiveSealedExecutable(f *os.File, digest string) (unix.Stat_t, error) {
	var before, after unix.Stat_t
	if f == nil {
		return before, errors.New("missing sealed executable")
	}
	if err := unix.Fstat(int(f.Fd()), &before); err != nil {
		return before, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&0o111 == 0 || before.Size <= 0 || before.Size > 128*1024*1024 {
		return before, errors.New("invalid runtime executable")
	}
	seals, err := unix.FcntlInt(f.Fd(), unix.F_GET_SEALS, 0)
	required := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if err != nil || seals&required != required {
		return before, errors.New("runtime executable is not fully sealed")
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(f, 0, before.Size)); err != nil {
		return before, err
	}
	if hex.EncodeToString(h.Sum(nil)) != digest {
		return before, errors.New("runtime executable digest mismatch")
	}
	if err := unix.Fstat(int(f.Fd()), &after); err != nil {
		return before, err
	}
	if before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mode != after.Mode {
		return before, errors.New("runtime executable changed")
	}
	return before, nil
}

// pinLiveRuntime waits for normal self-sealing within the original startup
// context, retaining both the kernel pidfd and the actual sealed executable.
// Only the process returned by ROOT's fixed spawn may be supplied here.
func pinLiveRuntime(ctx context.Context, child *os.Process) (*liveRuntimeIdentity, error) {
	return pinLiveRuntimeDigest(ctx, child, liveEngineDigest)
}
func pinLiveRuntimeDigest(ctx context.Context, child *os.Process, digest string) (*liveRuntimeIdentity, error) {
	if ctx == nil || child == nil || child.Pid <= 0 || ctx.Err() != nil {
		return nil, errors.New("invalid engine child")
	}
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline || !time.Now().Before(deadline) {
		return nil, errors.New("engine startup deadline required")
	}
	fd, err := unix.PidfdOpen(child.Pid, 0)
	if err != nil {
		return nil, err
	}
	p := &liveRuntimeIdentity{pid: child.Pid, pidfd: os.NewFile(uintptr(fd), "live-engine-pidfd")}
	ok := false
	defer func() {
		if !ok {
			_ = p.pidfd.Close()
		}
	}()
	p.start, err = session.ProcessIdentity(p.pid)
	if err != nil {
		return nil, err
	}
	var last error
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("sealed engine not established: %w", errors.Join(err, last))
		}
		if !time.Now().Before(deadline) {
			return nil, context.DeadlineExceeded
		}
		f, err := p.openExecutable()
		if err == nil {
			var st unix.Stat_t
			st, err = verifyLiveSealedExecutable(f, digest)
			if err == nil {
				p.dev, p.ino = st.Dev, st.Ino
				p.executable = f
				if err = p.verify(); err == nil {
					if err = ctx.Err(); err == nil && !time.Now().Before(deadline) {
						err = context.DeadlineExceeded
					}
					if err == nil {
						ok = true
						return p, nil
					}
				}
				p.executable = nil
			}
			_ = f.Close()
		}
		last = err
		if err = p.checkProcess(); err != nil {
			return nil, err
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, fmt.Errorf("sealed engine timeout: %w", errors.Join(ctx.Err(), last))
		case <-timer.C:
		}
	}
}

// verify brackets the currently executing object with trusted pidfd/start checks.
func (p *liveRuntimeIdentity) verify() error {
	if p == nil || p.executable == nil {
		return errors.New("missing pinned runtime executable")
	}
	flags, err := unix.FcntlInt(p.executable.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		return errors.New("runtime executable pin must be CLOEXEC")
	}
	var held unix.Stat_t
	if err := unix.Fstat(int(p.executable.Fd()), &held); err != nil {
		return err
	}
	if held.Dev != p.dev || held.Ino != p.ino {
		return errors.New("runtime executable pin changed")
	}
	f, err := p.openExecutable()
	if err != nil {
		return err
	}
	defer f.Close()
	var current unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &current); err != nil {
		return err
	}
	if current.Dev != p.dev || current.Ino != p.ino {
		return errors.New("engine executed a different image")
	}
	return p.checkProcess()
}
