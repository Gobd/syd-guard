//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Gobd/syd-guard/internal/session"
	"golang.org/x/sys/unix"
)

const liveBatchLimit = 256 * 1024

var liveEngineACK = []byte("{\"err\":0,\"msg\":\"ACK\"}\n")

// liveEngineEndpoint can only be constructed by ROOT from its fixed private
// layout and a newly dialed connection. The caller must already have protected
// that directory from the workload and obtained pid/start identity from the
// trusted supervisor; executable identity pinning remains a later startup gate.
// It never accepts a remote path or a controller-selected process.
type liveEngineEndpoint struct {
	dir, socket *os.File
	uid         uint32
	pid         int
	identity    string
	dial        func(context.Context) (*net.UnixConn, error)
}

func newLiveEngineEndpoint(dir, socket *os.File, uid uint32, pid int, identity string, dial func(context.Context) (*net.UnixConn, error)) (*liveEngineEndpoint, error) {
	if os.Geteuid() != 0 || dir == nil || socket == nil || pid <= 0 || identity == "" || dial == nil {
		return nil, errors.New("invalid root engine endpoint")
	}
	e := &liveEngineEndpoint{dir: dir, socket: socket, uid: uid, pid: pid, identity: identity, dial: dial}
	if err := e.checkSocket(); err != nil {
		return nil, err
	}
	return e, nil
}
func (e *liveEngineEndpoint) checkSocket() error {
	var held, named, dir unix.Stat_t
	if err := unix.Fstat(int(e.dir.Fd()), &dir); err != nil {
		return err
	}
	if dir.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("invalid private engine directory")
	}
	if err := unix.Fstat(int(e.socket.Fd()), &held); err != nil {
		return err
	}
	if err := unix.Fstatat(int(e.dir.Fd()), "s", &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if held.Mode&unix.S_IFMT != unix.S_IFSOCK || held.Uid != e.uid || held.Dev != named.Dev || held.Ino != named.Ino || named.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return errors.New("private engine socket identity changed")
	}
	for _, file := range []*os.File{e.dir, e.socket} {
		flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			return errors.New("engine endpoint FD must be CLOEXEC")
		}
	}
	return nil
}
func (e *liveEngineEndpoint) verifyPeer(c *net.UnixConn) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var result error
	if err = raw.Control(func(fd uintptr) {
		typ, x := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TYPE)
		if x != nil || typ != unix.SOCK_STREAM {
			result = errors.New("engine peer is not stream")
			return
		}
		flags, x := unix.FcntlInt(fd, unix.F_GETFD, 0)
		if x != nil || flags&unix.FD_CLOEXEC == 0 {
			result = errors.New("engine connection must be CLOEXEC")
			return
		}
		cred, x := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if x != nil || cred.Uid != e.uid || int(cred.Pid) != e.pid {
			result = errors.New("engine peer identity mismatch")
			return
		}
		addr, x := unix.Getpeername(int(fd))
		peer, ok := addr.(*unix.SockaddrUnix)
		if x != nil || !ok || peer.Name == "" || strings.HasPrefix(peer.Name, "@") || !filepath.IsAbs(peer.Name) || filepath.Clean(peer.Name) != peer.Name {
			result = errors.New("engine peer is not a named private connection")
			return
		}
		var bound, held unix.Stat_t
		if unix.Lstat(peer.Name, &bound) != nil || unix.Fstat(int(e.socket.Fd()), &held) != nil || bound.Mode&unix.S_IFMT != unix.S_IFSOCK || bound.Dev != held.Dev || bound.Ino != held.Ino {
			result = errors.New("engine connected socket identity mismatch")
		}
	}); err != nil {
		return err
	}
	if result != nil {
		return result
	}
	current, err := session.ProcessIdentity(e.pid)
	if err != nil || current != e.identity {
		return errors.New("engine process identity changed")
	}
	return e.checkSocket()
}
func sealedLiveBatch(data []byte) (*os.File, error) {
	if len(data) == 0 || len(data) > liveBatchLimit {
		return nil, errors.New("invalid live batch size")
	}
	fd, err := unix.MemfdCreate("sydguard-live-batch", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "live-batch")
	fail := func(e error) (*os.File, error) { _ = f.Close(); return nil, e }
	for b := data; len(b) > 0; {
		n, e := f.Write(b)
		if e != nil {
			return fail(e)
		}
		if n <= 0 {
			return fail(io.ErrShortWrite)
		}
		b = b[n:]
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return fail(err)
	}
	seals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if _, err = unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		return fail(err)
	}
	got, err := unix.FcntlInt(f.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || got&seals != seals {
		return fail(errors.New("live batch sealing failed"))
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size != int64(len(data)) {
		return fail(errors.New("invalid sealed batch"))
	}
	return f, nil
}

// load consumes the connected private engine stream and the sealed generated
// batch. It sends one exact load header and one descriptor, then requires the
// candidate's exact ACK followed by EOF; any uncertainty is a failed operation.
func (e *liveEngineEndpoint) load(ctx context.Context, data []byte) error {
	if ctx == nil {
		return errors.New("engine deadline required")
	}
	deadline, ok := ctx.Deadline()
	if !ok || ctx.Err() != nil {
		return errors.New("engine deadline required")
	}
	if err := e.checkSocket(); err != nil {
		return err
	}
	c, err := e.dial(ctx)
	if err != nil {
		return err
	}
	if c == nil {
		return errors.New("missing engine connection")
	}
	defer c.Close()
	if err = e.verifyPeer(c); err != nil {
		return err
	}
	if err = sendLiveEngineBatch(ctx, c, data); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return e.verifyPeer(c)
}

func sendLiveEngineBatch(ctx context.Context, c *net.UnixConn, data []byte) error {
	if ctx == nil || c == nil {
		return errors.New("engine deadline required")
	}
	deadline, ok := ctx.Deadline()
	if !ok || ctx.Err() != nil {
		return errors.New("engine deadline required")
	}
	if err := c.SetDeadline(deadline); err != nil {
		return err
	}
	joinCancelClose := watchEngineCancellation(ctx, c.Close)
	defer joinCancelClose()
	batch, err := sealedLiveBatch(data)
	if err != nil {
		return err
	}
	defer batch.Close()
	rights := unix.UnixRights(int(batch.Fd()))
	n, on, err := c.WriteMsgUnix([]byte("load\n"), rights, nil)
	if err != nil || n != 5 || on != len(rights) {
		return fmt.Errorf("incomplete one-FD engine load")
	}
	if err = readExactEngineACK(c); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

// watchEngineCancellation ensures no cancellation callback can outlive the
// operation and later close a descriptor reused by a subsequent operation.
func watchEngineCancellation(ctx context.Context, closeConn func() error) func() {
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(closed); _ = closeConn() })
	return func() {
		if !stop() {
			<-closed
		}
	}
}

func readExactEngineACK(c *net.UnixConn) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	data := make([]byte, 0, len(liveEngineACK)+1)
	for {
		buf := make([]byte, len(liveEngineACK)+1-len(data))
		if len(buf) == 0 {
			return errors.New("oversized engine ACK")
		}
		oob := make([]byte, unix.CmsgSpace(4*64))
		var n, on, flags int
		var recvErr error
		err = raw.Read(func(fd uintptr) bool {
			n, on, flags, _, recvErr = unix.Recvmsg(int(fd), buf, oob, unix.MSG_CMSG_CLOEXEC|unix.MSG_DONTWAIT)
			return recvErr != unix.EAGAIN && recvErr != unix.EINTR
		})
		if err != nil {
			return err
		}
		if on > 0 {
			closeWatchRights(oob[:on])
		}
		if on != 0 || flags & ^unix.MSG_CMSG_CLOEXEC != 0 {
			return errors.New("unexpected engine ACK ancillary data")
		}
		if recvErr != nil {
			return recvErr
		}
		if n == 0 {
			if !bytes.Equal(data, liveEngineACK) {
				return errors.New("invalid engine ACK")
			}
			return nil
		}
		data = append(data, buf[:n]...)
	}
}
