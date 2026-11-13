package guest

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ensureOverlayDir prepares startup bind targets without following symlinks.
func ensureOverlayDir(path string, create bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return fmt.Errorf("invalid overlay directory %q", path)
	}
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		next, e := unix.Openat(fd, part, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e == unix.ENOENT && create && i == len(parts)-1 {
			if e = unix.Mkdirat(fd, part, 0o755); e == nil || e == unix.EEXIST {
				next, e = unix.Openat(fd, part, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			}
		}
		_ = unix.Close(fd)
		if e != nil {
			return fmt.Errorf("overlay directory %s: %w", path, e)
		}
		fd = next
	}
	return unix.Close(fd)
}

// OverlayMount runs only in a short-lived helper process. Linux forbids entering
// a user namespace from a multithreaded process. Fork a single-thread child that
// uses ONLY raw syscalls, with signals blocked, and exits without returning to
// the Go runtime. The daemon never changes namespaces or gains capabilities.
//
//nolint:gosec // G103: pointers remain live across raw syscalls; child never enters the runtime.
func OverlayMount(pid int, source, target string, check bool) error {
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
	// Prepare all strings before fork. Walk them AFTER setns: mount target fds
	// opened in the parent's mount namespace cannot be used in the sandbox's.
	parts := func(path string) ([]*byte, error) {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
			return nil, fmt.Errorf("invalid overlay directory %q", path)
		}
		out := []*byte{}
		for _, p := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
			b, e := syscall.BytePtrFromString(p)
			if e != nil {
				return nil, e
			}
			out = append(out, b)
		}
		return out, nil
	}
	src, err := parts(source)
	if err != nil {
		return err
	}
	dst, err := parts(target)
	if err != nil {
		return err
	}
	slash, _ := syscall.BytePtrFromString("/")
	empty, _ := syscall.BytePtrFromString("")
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var old uint64
	mask := ^uint64(0)
	_, _, errno := syscall.RawSyscall6(unix.SYS_RT_SIGPROCMASK, unix.SIG_SETMASK, uintptr(unsafe.Pointer(&mask)), uintptr(unsafe.Pointer(&old)), 8, 0, 0)
	if errno != 0 {
		return errno
	}
	child, errno := forkOverlay(user.Fd(), mnt.Fd(), src, dst, slash, empty, check)
	_, _, restore := syscall.RawSyscall6(unix.SYS_RT_SIGPROCMASK, unix.SIG_SETMASK, uintptr(unsafe.Pointer(&old)), 0, 8, 0, 0)
	runtime.KeepAlive(src)
	runtime.KeepAlive(dst)
	runtime.KeepAlive(slash)
	runtime.KeepAlive(empty)
	if errno != 0 {
		return errno
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
		return fmt.Errorf("overlay helper failed (status %v, errno %d)", status, status.ExitStatus())
	}
	if restore != 0 {
		return restore
	}
	return nil
}

// Raw, no-follow directory walk. Only the final target component may be created.
// All fds are opened within the entered mount namespace. No /proc magic links.
//
//go:nosplit
//go:norace
//nolint:gosec // G103: preallocated byte strings, syscall ABI pointers only.
func overlayDirRaw(parts []*byte, slash *byte, create bool) (uintptr, syscall.Errno) {
	fd, _, err := syscall.RawSyscall6(unix.SYS_OPENAT, ^uintptr(99), uintptr(unsafe.Pointer(slash)), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0, 0, 0)
	if err != 0 {
		return fd, err
	}
	for i, part := range parts {
		next, _, e := syscall.RawSyscall6(unix.SYS_OPENAT, fd, uintptr(unsafe.Pointer(part)), unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0, 0, 0)
		if e == syscall.ENOENT && create && i == len(parts)-1 {
			_, _, e = syscall.RawSyscall(unix.SYS_MKDIRAT, fd, uintptr(unsafe.Pointer(part)), 0o755)
			if e == 0 || e == syscall.EEXIST {
				next, _, e = syscall.RawSyscall6(unix.SYS_OPENAT, fd, uintptr(unsafe.Pointer(part)), unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0, 0, 0)
			}
		}
		_, _, _ = syscall.RawSyscall(unix.SYS_CLOSE, fd, 0, 0)
		if e != 0 {
			return next, e
		}
		fd = next
	}
	return fd, 0
}

// No allocation, stack growth, scheduling, defers, or runtime calls between
// clone and exit. SIGCHLD-only clone has fork semantics on amd64 and arm64.
// open_tree + move_mount bind the pinned directory objects, avoiding path races.
//
//go:nosplit
//go:norace
//nolint:gosec // G103: preallocated byte strings, syscall ABI pointers only.
func forkOverlay(user, mnt uintptr, source, target []*byte, slash, empty *byte, checkOnly bool) (uintptr, syscall.Errno) {
	pid, _, errno := syscall.RawSyscall6(unix.SYS_CLONE, uintptr(syscall.SIGCHLD), 0, 0, 0, 0, 0)
	if errno != 0 || pid != 0 {
		return pid, errno
	}
	_, _, errno = syscall.RawSyscall(unix.SYS_SETNS, user, unix.CLONE_NEWUSER, 0)
	if errno == 0 {
		_, _, errno = syscall.RawSyscall(unix.SYS_SETNS, mnt, unix.CLONE_NEWNS, 0)
	}
	var src, dst, tree uintptr
	if errno == 0 {
		src, errno = overlayDirRaw(source, slash, false)
	}
	if errno == 0 {
		dst, errno = overlayDirRaw(target, slash, !checkOnly)
	}
	if errno == 0 && !checkOnly {
		tree, _, errno = syscall.RawSyscall(unix.SYS_OPEN_TREE, src, uintptr(unsafe.Pointer(empty)), unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_EMPTY_PATH)
	}
	if errno == 0 && !checkOnly {
		_, _, errno = syscall.RawSyscall6(unix.SYS_MOVE_MOUNT, tree, uintptr(unsafe.Pointer(empty)), dst, uintptr(unsafe.Pointer(empty)), unix.MOVE_MOUNT_F_EMPTY_PATH|unix.MOVE_MOUNT_T_EMPTY_PATH, 0)
	}
	// Confirm a fresh no-follow lookup sees the mounted source, not a renamed
	// target object. Later renames remain a documented best-effort limitation.
	if errno == 0 {
		var check uintptr
		var a, b unix.Stat_t
		check, errno = overlayDirRaw(target, slash, false)
		if errno == 0 {
			_, _, errno = syscall.RawSyscall(unix.SYS_FSTAT, src, uintptr(unsafe.Pointer(&a)), 0)
		}
		if errno == 0 {
			_, _, errno = syscall.RawSyscall(unix.SYS_FSTAT, check, uintptr(unsafe.Pointer(&b)), 0)
		}
		if errno == 0 && (a.Dev != b.Dev || a.Ino != b.Ino) {
			errno = syscall.ESTALE
		}
	}
	for {
		_, _, _ = syscall.RawSyscall(unix.SYS_EXIT_GROUP, uintptr(errno), 0, 0)
	}
}
