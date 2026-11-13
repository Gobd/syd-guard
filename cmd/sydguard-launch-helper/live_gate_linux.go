//go:build linux

package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/Gobd/syd-guard/internal/managedlive"
	"github.com/Gobd/syd-guard/internal/syd"
	"golang.org/x/sys/unix"
)

const liveGateReleaseFD = syd.FixedReleaseFD
const liveGateFrameSize = 65

// liveGateInput is held only by the ordinary gate; these values are selected by
// the ROOT parent and never include policy bytes, credentials or ROOT FDs.
type liveGateInput struct {
	nonce, ticket [32]byte
	accepted      uint64
	uid, gid      uint32
	argv, env     []string
	executable    string
}

func decodeGateID(s string) ([32]byte, error) {
	var id [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 || hex.EncodeToString(b) != s {
		return id, errors.New("invalid gate binding")
	}
	copy(id[:], b)
	return id, nil
}
func liveGateFrame(nonce, ticket [32]byte) [liveGateFrameSize]byte {
	var b [liveGateFrameSize]byte
	b[0] = 'R'
	copy(b[1:33], nonce[:])
	copy(b[33:], ticket[:])
	return b
}
func parseLiveGateInput(args []string, env []string) (liveGateInput, error) {
	var in liveGateInput
	if len(args) < 8 || args[0] != "--live-gate" || args[6] != "--" || len(args)-7 > 256 {
		return in, errors.New("invalid gate invocation")
	}
	var err error
	in.nonce, err = decodeGateID(args[1])
	if err != nil {
		return in, err
	}
	in.ticket, err = decodeGateID(args[2])
	if err != nil {
		return in, err
	}
	in.accepted, err = strconv.ParseUint(args[3], 10, 64)
	if err != nil || in.accepted == 0 || in.accepted > ^uint64(0)-uint64(managedlive.StartupTimeout) {
		return in, errors.New("invalid gate deadline")
	}
	uid, err := strconv.ParseUint(args[4], 10, 31)
	if err != nil || uid == 0 {
		return in, errors.New("invalid gate UID")
	}
	gid, err := strconv.ParseUint(args[5], 10, 31)
	if err != nil || gid == 0 {
		return in, errors.New("invalid gate GID")
	}
	in.uid, in.gid = uint32(uid), uint32(gid)
	in.argv = append([]string(nil), args[7:]...)
	for _, arg := range in.argv {
		if len(arg) > 32768 || strings.ContainsRune(arg, 0) {
			return in, errors.New("invalid gate argument")
		}
	}
	if len(in.argv) == 0 || in.argv[0] == "" {
		return in, errors.New("missing gate executable")
	}
	if len(env) > 128 {
		return in, errors.New("invalid gate environment")
	}
	seen := map[string]bool{}
	total := 0
	for _, entry := range env {
		total += len(entry)
		key, value, ok := strings.Cut(entry, "=")
		if !ok || seen[key] || len(entry) > 4096 || strings.ContainsRune(entry, 0) {
			return in, errors.New("invalid gate environment")
		}
		seen[key] = true
		switch key {
		case "PATH":
			if value != "/usr/bin:/bin" {
				return in, errors.New("invalid gate PATH")
			}
			in.env = append(in.env, entry)
		case "HOME", "XDG_CONFIG_HOME", "TMPDIR", "SYDGUARD_TMPDIR", "SYDGUARD_SELECTED_PROFILE", "SYDGUARD_PROJECT_ID", "SYDGUARD_PROFILE_NAME", "SYDGUARD_PROFILE_REVISION":
			in.env = append(in.env, entry)
		default:
			return in, errors.New("unexpected gate environment")
		}
	}
	if total > 32768 || !seen["PATH"] {
		return in, errors.New("invalid gate environment")
	}
	in.executable, err = exec.LookPath(in.argv[0])
	if err != nil {
		return in, err
	}
	return in, nil
}
func checkLiveGateCredentials() error {
	if os.Getuid() <= 0 || os.Geteuid() != os.Getuid() || os.Getgid() != os.Getegid() {
		return errors.New("gate requires ordinary credentials")
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 {
		return errors.New("gate supplementary groups not cleared")
	}
	nnp, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil || nnp != 1 {
		return errors.New("gate requires no-new-privileges")
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var caps [2]unix.CapUserData
	if err := unix.Capget(&header, &caps[0]); err != nil {
		return err
	}
	for _, entry := range caps {
		if entry.Effective != 0 || entry.Permitted != 0 || entry.Inheritable != 0 {
			return errors.New("gate capability set is not empty")
		}
	}
	for cap := 0; cap <= unix.CAP_LAST_CAP; cap++ {
		value, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, uintptr(cap), 0, 0, 0)
		if err != nil || value != 0 {
			return errors.New("gate capability bounding set is not empty")
		}
	}
	return nil
}
func checkLiveGatePipe(fd int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFIFO {
		return errors.New("gate release is not a pipe")
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		return errors.New("gate release pipe is not read-only")
	}
	unix.CloseOnExec(fd)
	return nil
}

// holdLiveGate verifies a fixed frame and EOF while non-dumpable. Release is
// rejected if the original watchdog deadline has passed. The caller supplies
// only ROOT-derived pipe/nonce/ticket and must close every other authority FD.
func holdLiveGate(fd int, nonce, ticket [32]byte, accepted uint64) error {
	return holdLiveGateWithClockPoll(fd, nonce, ticket, accepted, monotonicNanoseconds, unix.Poll)
}

func liveGateDeadline(clock func() (uint64, error), deadline uint64) (uint64, error) {
	now, err := clock()
	if err != nil {
		return 0, err
	}
	if now >= deadline {
		return 0, errors.New("gate startup deadline")
	}
	return now, nil
}

func holdLiveGateWithClockPoll(fd int, nonce, ticket [32]byte, accepted uint64, clock func() (uint64, error), poll func([]unix.PollFd, int) (int, error)) error {
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}()
	if accepted == 0 || accepted > ^uint64(0)-uint64(managedlive.StartupTimeout) {
		return errors.New("invalid gate deadline")
	}
	if err := checkLiveGatePipe(fd); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return err
	}
	dump, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil || dump != 0 {
		return errors.New("gate is dumpable")
	}
	deadline := accepted + uint64(managedlive.StartupTimeout)
	var actual [liveGateFrameSize + 1]byte
	used := 0
	for {
		now, err := liveGateDeadline(clock, deadline)
		if err != nil {
			return err
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLHUP}}
		n, err := poll(fds, livePollTimeout(now, deadline))
		if _, deadlineErr := liveGateDeadline(clock, deadline); deadlineErr != nil {
			return deadlineErr
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		if fds[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
			return errors.New("gate release pipe error")
		}
		nread, err := unix.Read(fd, actual[used:])
		if _, deadlineErr := liveGateDeadline(clock, deadline); deadlineErr != nil {
			return deadlineErr
		}
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
			continue
		}
		if err != nil {
			return err
		}
		if nread == 0 {
			expected := liveGateFrame(nonce, ticket)
			if used != len(expected) || !bytes.Equal(actual[:used], expected[:]) {
				return errors.New("invalid gate release")
			}
			break
		}
		used += nread
		if used == len(actual) {
			return errors.New("oversized gate release")
		}
	}
	if _, err := liveGateDeadline(clock, deadline); err != nil {
		return err
	}
	closeErr := unix.Close(fd)
	fd = -1
	if closeErr != nil {
		return closeErr
	}
	if _, err := liveGateDeadline(clock, deadline); err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 1, 0, 0, 0); err != nil {
		return err
	}
	dump, err = unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil || dump != 1 {
		return errors.New("cannot restore tracee dumpability")
	}
	if _, err := liveGateDeadline(clock, deadline); err != nil {
		_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
		return err
	}
	return nil
}
func liveGateMain() (int, error) {
	// Reject privileged invocation before inspecting any caller-selected args.
	if err := checkLiveGateCredentials(); err != nil {
		return 1, err
	}
	in, err := parseLiveGateInput(os.Args[1:], os.Environ())
	if err != nil {
		return 1, err
	}
	if uint32(os.Getuid()) != in.uid || uint32(os.Getgid()) != in.gid {
		return 1, errors.New("gate identity mismatch")
	}
	if err = holdLiveGate(liveGateReleaseFD, in.nonce, in.ticket, in.accepted); err != nil {
		return 1, err
	}
	if _, err = liveGateDeadline(monotonicNanoseconds, in.accepted+uint64(managedlive.StartupTimeout)); err != nil {
		_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
		return 1, err
	}
	if err = syscall.Exec(in.executable, in.argv, in.env); err != nil {
		return 1, fmt.Errorf("gate exec: %w", err)
	}
	return 1, errors.New("gate exec returned")
}
