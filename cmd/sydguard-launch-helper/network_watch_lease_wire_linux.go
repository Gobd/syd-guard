//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"golang.org/x/sys/unix"
)

// This is a dedicated inherited stream, not the live watchdog operation stream.
// A frame is not peer authentication. The nonce is the root journal's fresh
// 32-byte lifecycle generation, not a caller-selected namespace name.
const networkWatchLeaseFrameSize = 100
const (
	networkWatchLease      byte = 1
	networkWatchLeaseACK   byte = 2
	networkWatchRecover    byte = 3
	networkWatchRecoverACK byte = 4
	networkWatchRelease    byte = 5
	networkWatchReleaseACK byte = 6
	networkWatchParent     byte = 1
	networkWatchWatchdog   byte = 2
)

type networkWatchLeaseFrame struct {
	op, role           byte
	uid, index         uint32
	nonce              [32]byte
	dev, ino, sequence uint64
	retentionToken     [32]byte
}

func (f networkWatchLeaseFrame) bytes() [networkWatchLeaseFrameSize]byte {
	var b [networkWatchLeaseFrameSize]byte
	b[0], b[1], b[2], b[3] = 'N', 1, f.op, f.role
	binary.BigEndian.PutUint32(b[4:8], f.uid)
	binary.BigEndian.PutUint32(b[8:12], f.index)
	copy(b[12:44], f.nonce[:])
	binary.BigEndian.PutUint64(b[44:52], f.dev)
	binary.BigEndian.PutUint64(b[52:60], f.ino)
	binary.BigEndian.PutUint64(b[60:68], f.sequence)
	copy(b[68:100], f.retentionToken[:])
	return b
}
func decodeNetworkWatchLeaseFrame(b []byte) (networkWatchLeaseFrame, error) {
	var f networkWatchLeaseFrame
	if len(b) != networkWatchLeaseFrameSize || b[0] != 'N' || b[1] != 1 {
		return f, errors.New("invalid network lease frame header")
	}
	f.op, f.role = b[2], b[3]
	f.uid = binary.BigEndian.Uint32(b[4:8])
	f.index = binary.BigEndian.Uint32(b[8:12])
	copy(f.nonce[:], b[12:44])
	f.dev = binary.BigEndian.Uint64(b[44:52])
	f.ino = binary.BigEndian.Uint64(b[52:60])
	f.sequence = binary.BigEndian.Uint64(b[60:68])
	copy(f.retentionToken[:], b[68:100])
	return f, nil
}
func checkNetworkLeaseStream(fd int) error {
	typ, e := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if e != nil || typ != unix.SOCK_STREAM {
		return errors.New("network lease requires stream socket")
	}
	domain, e := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	if e != nil || domain != unix.AF_UNIX {
		return errors.New("network lease requires Unix socket")
	}
	return nil
}

// pollNetworkLease observes the pinned peer lifetime before socket readiness.
// A context cancellation needs no detached polling goroutine.
func pollNetworkLease(ctx context.Context, socket, peer int, event int16) error {
	if socket < 0 || peer < 0 {
		return errors.New("invalid lease channel or peer pin")
	}
	fds := []unix.PollFd{{Fd: int32(peer), Events: unix.POLLIN}, {Fd: int32(socket), Events: event | unix.POLLHUP}} //nolint:gosec // Linux fds fit int32
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		ms := 20
		if deadline, ok := ctx.Deadline(); ok {
			left := time.Until(deadline)
			if left <= 0 {
				return context.DeadlineExceeded
			}
			if left < 20*time.Millisecond {
				ms = int((left + time.Millisecond - 1) / time.Millisecond)
			}
		}
		fds[0].Revents = 0
		fds[1].Revents = 0
		_, err := unix.Poll(fds, ms)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if fds[0].Revents != 0 {
			return errors.New("network lease peer exited or identity pin failed")
		}
		if fds[1].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return errors.New("network lease channel closed")
		}
		if fds[1].Revents&event != 0 {
			return nil
		}
	}
}

// Each rights-bearing send attaches exactly one FD to the first byte. Partial
// sends continue without ancillary data; an error poisons the transaction.
func sendNetworkWatchLeaseFrame(ctx context.Context, socket, peer int, frame networkWatchLeaseFrame, fd int) error {
	data := frame.bytes()
	sent := 0
	for sent < len(data) {
		if err := pollNetworkLease(ctx, socket, peer, unix.POLLOUT); err != nil {
			return err
		}
		var rights []byte
		if sent == 0 && fd >= 0 {
			rights = unix.UnixRights(fd)
		}
		n, err := unix.SendmsgN(socket, data[sent:], rights, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL)
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
			continue
		}
		if err != nil {
			return err
		}
		if n <= 0 || n > len(data)-sent {
			return io.ErrShortWrite
		}
		sent += n
	}
	return ctx.Err()
}

// recvNetworkWatchLeaseFrame owns and closes every received descriptor unless
// it returns the sole explicitly expected one. Never use Read on this stream:
// it would discard ancillary data without authenticating its presence.
// expectedFD is -1 for an as-yet-undecoded request, 0 for none, 1 for one.
func recvNetworkWatchLeaseFrame(ctx context.Context, socket, peer int, expectedFD int) (networkWatchLeaseFrame, int, error) {
	var frame networkWatchLeaseFrame
	var buf [networkWatchLeaseFrameSize]byte
	received := -1
	pos := 0
	fail := func(e error) (networkWatchLeaseFrame, int, error) {
		if received >= 0 {
			_ = unix.Close(received)
		}
		return networkWatchLeaseFrame{}, -1, e
	}
	for pos < len(buf) {
		if err := pollNetworkLease(ctx, socket, peer, unix.POLLIN); err != nil {
			return fail(err)
		}
		control := make([]byte, unix.CmsgSpace(4*16))
		n, oobn, flags, _, err := unix.Recvmsg(socket, buf[pos:], control, unix.MSG_DONTWAIT|unix.MSG_CMSG_CLOEXEC)
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
			continue
		}
		if err != nil {
			return fail(err)
		}
		messages, parseErr := unix.ParseSocketControlMessage(control[:oobn])
		var fds []int
		valid := parseErr == nil
		for _, m := range messages {
			if m.Header.Level != unix.SOL_SOCKET || m.Header.Type != unix.SCM_RIGHTS {
				valid = false
				continue
			}
			v, e := unix.ParseUnixRights(&m)
			if e != nil {
				valid = false
				continue
			}
			fds = append(fds, v...)
		}
		if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || !valid || len(fds) > 1 || (len(fds) == 1 && (expectedFD == 0 || pos != 0 || received >= 0)) {
			for _, fd := range fds {
				_ = unix.Close(fd)
			}
			return fail(errors.New("invalid network lease ancillary data"))
		}
		if len(fds) == 1 {
			received = fds[0]
		}
		if n <= 0 {
			return fail(io.EOF)
		}
		pos += n
	}
	if expectedFD < -1 || expectedFD > 1 || (expectedFD == 1 && received < 0) || (expectedFD == 0 && received >= 0) {
		return fail(errors.New("network lease descriptor count mismatch"))
	}
	frame, err := decodeNetworkWatchLeaseFrame(buf[:])
	if err != nil {
		return fail(err)
	}
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	return frame, received, nil
}
