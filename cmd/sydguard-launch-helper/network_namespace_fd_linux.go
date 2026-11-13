//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// verifyNetworkNamespaceFD authenticates the kernel namespace object, not a
// pathname in the watchdog's independently cloned mount namespace.
func verifyNetworkNamespaceFD(fd int, object networkObject) error {
	if fd < 0 || object.Kind != "namespace" || object.Dev == 0 || object.Ino == 0 {
		return errors.New("invalid network namespace binding")
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return err
	}
	if st.Dev != object.Dev || st.Ino != object.Ino || uint64(fs.Type) != uint64(unix.NSFS_MAGIC) {
		return errors.New("network namespace identity changed")
	}
	kind, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
	if err != nil || kind != unix.CLONE_NEWNET {
		return errors.New("descriptor is not a network namespace")
	}
	return nil
}

func checkNamespaceChannel(fd int) error {
	kind, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || kind != unix.SOCK_SEQPACKET {
		return errors.New("invalid namespace handoff socket type")
	}
	domain, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	if err != nil || domain != unix.AF_UNIX {
		return errors.New("invalid namespace handoff socket domain")
	}
	return nil
}

func waitNamespaceChannel(ctx context.Context, fd int, events int16) error {
	poll := []unix.PollFd{{Fd: int32(fd), Events: events}} //nolint:gosec // kernel file descriptor fits int32
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		timeout := 100 * time.Millisecond
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < timeout {
			timeout = time.Until(deadline)
		}
		if timeout <= 0 {
			return context.DeadlineExceeded
		}
		ms := int((timeout + time.Millisecond - 1) / time.Millisecond)
		n, err := unix.Poll(poll, ms)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if n > 0 {
			if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
				return errors.New("namespace handoff channel closed")
			}
			if poll[0].Revents&events != 0 {
				return nil
			}
		}
	}
}

// sendNetworkNamespace sends exactly one verified nsfs descriptor over the
// exclusive parent/watchdog channel. It is not a peer authentication protocol.
func sendNetworkNamespace(ctx context.Context, socket int, ns *os.File, object networkObject) error {
	if ns == nil {
		return errors.New("missing network namespace descriptor")
	}
	if err := checkNamespaceChannel(socket); err != nil {
		return err
	}
	if err := verifyNetworkNamespaceFD(int(ns.Fd()), object); err != nil {
		return err
	}
	rights := unix.UnixRights(int(ns.Fd()))
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := unix.SendmsgN(socket, []byte{'N'}, rights, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EAGAIN) {
			if err := waitNamespaceChannel(ctx, socket, unix.POLLOUT); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if n != 1 {
			return errors.New("incomplete namespace handoff")
		}
		return nil
	}
}

// receiveNetworkNamespace closes all unexpected received FDs and takes
// ownership only after verifying nsfs type and the root-journalled identity.
func receiveNetworkNamespace(ctx context.Context, socket int, object networkObject) (*os.File, error) {
	if err := checkNamespaceChannel(socket); err != nil {
		return nil, err
	}
	var payload [2]byte
	control := make([]byte, unix.CmsgSpace(8*4))
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, oobn, flags, _, err := unix.Recvmsg(socket, payload[:], control, unix.MSG_DONTWAIT|unix.MSG_CMSG_CLOEXEC)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EAGAIN) {
			if err := waitNamespaceChannel(ctx, socket, unix.POLLIN); err != nil {
				return nil, err
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		messages, parseErr := unix.ParseSocketControlMessage(control[:oobn])
		var fds []int
		valid := parseErr == nil
		for _, message := range messages {
			if message.Header.Level != unix.SOL_SOCKET || message.Header.Type != unix.SCM_RIGHTS {
				valid = false
				continue
			}
			rights, err := unix.ParseUnixRights(&message)
			if err != nil {
				valid = false
				continue
			}
			fds = append(fds, rights...)
		}
		closeAll := func() {
			for _, fd := range fds {
				_ = unix.Close(fd)
			}
		}
		if !valid || n != 1 || payload[0] != 'N' || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || len(fds) != 1 {
			closeAll()
			return nil, errors.New("invalid network namespace handoff")
		}
		if err := verifyNetworkNamespaceFD(fds[0], object); err != nil {
			closeAll()
			return nil, err
		}
		return os.NewFile(uintptr(fds[0]), "network-namespace"), nil
	}
}
