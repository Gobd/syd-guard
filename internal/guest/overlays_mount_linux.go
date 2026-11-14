package guest

import (
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// OverlayMount runs in a short-lived helper process. It bind-mounts source over
// target inside the mount namespace of sandbox process pid.
//
// The sandbox maps only the user's own uid, so nsenter can't do this: exec as
// a non-root uid drops the capabilities setns grants. And a Go process can't
// setns into a user namespace (it is multithreaded). So fork a single-threaded
// child that makes only raw syscalls, like the child half of syscall.forkExec:
// setns(user), setns(mnt), mount, exit. It never returns to the Go runtime.
func OverlayMount(pid int, source, target string) error {
	user, err := os.Open(fmt.Sprintf("/proc/%d/ns/user", pid))
	if err != nil {
		return err
	}
	defer func() { _ = user.Close() }()
	mnt, err := os.Open(fmt.Sprintf("/proc/%d/ns/mnt", pid))
	if err != nil {
		return err
	}
	defer func() { _ = mnt.Close() }()
	src, err := syscall.BytePtrFromString(source)
	if err != nil {
		return err
	}
	dst, err := syscall.BytePtrFromString(target)
	if err != nil {
		return err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// No signal handler may run in the child: block all signals around clone.
	var old uint64
	all := ^uint64(0)
	if _, _, e := syscall.RawSyscall6(unix.SYS_RT_SIGPROCMASK, unix.SIG_SETMASK, uintptr(unsafe.Pointer(&all)), uintptr(unsafe.Pointer(&old)), 8, 0, 0); e != 0 { //nolint:gosec // G103: syscall ABI
		return e
	}
	child, e := overlayChild(user.Fd(), mnt.Fd(), src, dst)
	_, _, _ = syscall.RawSyscall6(unix.SYS_RT_SIGPROCMASK, unix.SIG_SETMASK, uintptr(unsafe.Pointer(&old)), 0, 8, 0, 0) //nolint:gosec // G103: syscall ABI
	runtime.KeepAlive(src)
	runtime.KeepAlive(dst)
	if e != 0 {
		return fmt.Errorf("fork: %w", e)
	}
	var status syscall.WaitStatus
	for {
		_, err = syscall.Wait4(int(child), &status, 0, nil)
		if err != syscall.EINTR {
			break
		}
	}
	if err != nil {
		return err
	}
	if !status.Exited() || status.ExitStatus() != 0 {
		return fmt.Errorf("mount in sandbox namespace: %w", syscall.Errno(status.ExitStatus()))
	}
	return nil
}

// overlayChild: no allocation, stack growth, scheduling or runtime calls
// between clone and exit. Exit status is the failing errno (0 = mounted).
//
//go:nosplit
//go:norace
func overlayChild(user, mnt uintptr, src, dst *byte) (uintptr, syscall.Errno) {
	pid, _, e := syscall.RawSyscall6(unix.SYS_CLONE, uintptr(syscall.SIGCHLD), 0, 0, 0, 0, 0)
	if e != 0 || pid != 0 {
		return pid, e
	}
	_, _, e = syscall.RawSyscall(unix.SYS_SETNS, user, unix.CLONE_NEWUSER, 0)
	if e == 0 {
		_, _, e = syscall.RawSyscall(unix.SYS_SETNS, mnt, unix.CLONE_NEWNS, 0)
	}
	if e == 0 {
		_, _, e = syscall.RawSyscall6(unix.SYS_MOUNT, uintptr(unsafe.Pointer(src)), uintptr(unsafe.Pointer(dst)), 0, unix.MS_BIND|unix.MS_REC, 0, 0) //nolint:gosec // G103: syscall ABI
	}
	for {
		_, _, _ = syscall.RawSyscall(unix.SYS_EXIT_GROUP, uintptr(e), 0, 0)
	}
}

// mountedIn reports whether target is a mount point in pid's mount namespace.
func mountedIn(pid int, target string) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if f := strings.Fields(line); len(f) > 4 && f[4] == target {
			return true
		}
	}
	return false
}

// hostShares lists mounts backed by the host (Lima's virtiofs/9p/sshfs, NFS,
// SMB): writes there reach the host's disk.
func hostShares() []string {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		pre, post, ok := strings.Cut(line, " - ")
		f, g := strings.Fields(pre), strings.Fields(post)
		if !ok || len(f) < 5 || len(g) < 1 || strings.Contains(f[4], `\`) {
			continue
		}
		switch g[0] {
		case "virtiofs", "9p", "fuse.sshfs", "nfs", "nfs4", "cifs", "smb3":
			if !slices.Contains(out, f[4]) {
				out = append(out, f[4])
			}
		}
	}
	return out
}
