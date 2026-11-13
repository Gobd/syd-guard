//go:build linux

package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/session"
	"golang.org/x/sys/unix"
)

func enginePair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	p, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	convert := func(fd int) *net.UnixConn {
		f := os.NewFile(uintptr(fd), "socket")
		c, err := net.FileConn(f)
		_ = f.Close()
		if err != nil {
			t.Fatal(err)
		}
		return c.(*net.UnixConn)
	}
	a, b := convert(p[0]), convert(p[1])
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}
func receiveEngineBatch(c *net.UnixConn) ([]byte, error) {
	b := make([]byte, 16)
	oob := make([]byte, unix.CmsgSpace(4*4))
	n, on, flags, _, readErr := c.ReadMsgUnix(b, oob)
	msgs, parseErr := unix.ParseSocketControlMessage(oob[:on])
	var fds []int
	var rightsErr error
	for _, msg := range msgs {
		got, err := unix.ParseUnixRights(&msg)
		if err != nil {
			rightsErr = err
		} else {
			fds = append(fds, got...)
		}
	}
	defer func() {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
	}()
	if readErr != nil {
		return nil, readErr
	}
	if flags & ^unix.MSG_CMSG_CLOEXEC != 0 || string(b[:n]) != "load\n" || parseErr != nil || rightsErr != nil || len(msgs) != 1 || len(fds) != 1 {
		return nil, io.ErrUnexpectedEOF
	}
	f := os.NewFile(uintptr(fds[0]), "received-batch")
	fds = nil // f owns the only received descriptor.
	defer f.Close()
	seals, err := unix.FcntlInt(f.Fd(), unix.F_GET_SEALS, 0)
	want := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if err != nil || seals&want != want {
		return nil, io.ErrUnexpectedEOF
	}
	if _, err := f.Write([]byte("bad")); err == nil {
		return nil, io.ErrUnexpectedEOF
	}
	return io.ReadAll(f)
}
func TestLiveEngineReceiveMsgFlags(t *testing.T) {
	a, b := enginePair(t)
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, _, err := a.WriteMsgUnix([]byte("x"), unix.UnixRights(int(f.Fd())), nil); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	_, on, flags, _, err := b.ReadMsgUnix(data, oob)
	if on > 0 {
		closeWatchRights(oob[:on])
	}
	t.Logf("recvmsg flags=%#x MSG_CMSG_CLOEXEC=%#x", flags, unix.MSG_CMSG_CLOEXEC)
	if err != nil || flags & ^unix.MSG_CMSG_CLOEXEC != 0 {
		t.Fatalf("unexpected receive flags: %#x %v", flags, err)
	}
}

func TestLiveEngineRejectsHeaderAndClosesAllRights(t *testing.T) {
	a, b := enginePair(t)
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = a.WriteMsgUnix([]byte("wrong\n"), unix.UnixRights(int(f.Fd()), int(f.Fd())), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := receiveEngineBatch(b); err == nil {
		t.Fatal("bad header and multiple rights accepted")
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("received rights leaked: %d -> %d", len(before), len(after))
	}
}

func TestLiveEngineCancellationWatcherJoined(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	entered, release, joined := make(chan struct{}), make(chan struct{}), make(chan struct{})
	join := watchEngineCancellation(ctx, func() error { close(entered); <-release; return nil })
	cancel()
	<-entered
	go func() { join(); close(joined) }()
	select {
	case <-joined:
		t.Fatal("join returned before callback finished")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("callback join stalled")
	}
}

func TestLiveEngineOneFDSealedACK(t *testing.T) {
	a, b := enginePair(t)
	done := make(chan error, 1)
	payload := []byte("cmd/move!default\n")
	go func() {
		got, err := receiveEngineBatch(b)
		if err == nil && !bytes.Equal(got, payload) {
			err = io.ErrUnexpectedEOF
		}
		if err == nil {
			_, err = b.Write(liveEngineACK)
		}
		_ = b.Close()
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := sendLiveEngineBatch(ctx, a, payload); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
func TestLiveEngineACKRejectsMalformedAndAncillary(t *testing.T) {
	for _, bad := range [][]byte{[]byte("{\"err\":0,\"msg\":\"ACK\"}"), []byte("{\"err\":0,\"err\":0,\"msg\":\"ACK\"}\n"), append(append([]byte(nil), liveEngineACK...), 'x'), []byte("{\"err\":1,\"msg\":\"ACK\"}\n")} {
		a, b := enginePair(t)
		done := make(chan error, 1)
		go func() {
			_, err := receiveEngineBatch(b)
			if err == nil {
				_, err = b.Write(bad)
			}
			_ = b.Close()
			done <- err
		}()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := sendLiveEngineBatch(ctx, a, []byte("x"))
		cancel()
		if err == nil {
			t.Fatalf("accepted bad ACK %q", bad)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	a, b := enginePair(t)
	done := make(chan error, 1)
	go func() {
		_, err := receiveEngineBatch(b)
		if err == nil {
			f, e := os.Open(os.DevNull)
			if e != nil {
				err = e
			} else {
				_, _, err = b.WriteMsgUnix(liveEngineACK, unix.UnixRights(int(f.Fd())), nil)
				_ = f.Close()
			}
		}
		_ = b.Close()
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := sendLiveEngineBatch(ctx, a, []byte("x")); err == nil {
		t.Fatal("ACK with FD accepted")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
func TestLiveEngineCancellationAndBatchBounds(t *testing.T) {
	if _, err := sealedLiveBatch(nil); err == nil {
		t.Fatal("empty batch")
	}
	if _, err := sealedLiveBatch(make([]byte, liveBatchLimit+1)); err == nil {
		t.Fatal("oversized batch")
	}
	a, b := enginePair(t)
	done := make(chan error, 1)
	go func() { _, err := receiveEngineBatch(b); done <- err }()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := sendLiveEngineBatch(ctx, a, []byte("x")); err == nil || time.Since(start) > time.Second {
		t.Fatal("cancel did not bound ACK", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
func TestLiveEngineACKWithoutEOFIsUnknown(t *testing.T) {
	a, b := enginePair(t)
	done := make(chan error, 1)
	go func() {
		_, err := receiveEngineBatch(b)
		if err == nil {
			_, err = b.Write(liveEngineACK)
		}
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := sendLiveEngineBatch(ctx, a, []byte("x")); err == nil {
		t.Fatal("unterminated ACK accepted")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLiveEngineGenuinePeerAndPinnedSocket(t *testing.T) {
	root, err := os.MkdirTemp("", "sgipc-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	path := filepath.Join(root, "s")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	dfd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	dir := os.NewFile(uintptr(dfd), "dir")
	defer dir.Close()
	sfd, err := unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	sock := os.NewFile(uintptr(sfd), "socket")
	defer sock.Close()
	identity, err := session.ProcessIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	endpoint := &liveEngineEndpoint{dir: dir, socket: sock, uid: uint32(os.Getuid()), pid: os.Getpid(), identity: identity}
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := endpoint.verifyPeer(c); err != nil {
		t.Fatal(err)
	}
	pair, _ := enginePair(t)
	if err := endpoint.verifyPeer(pair); err == nil {
		t.Fatal("pre-fork socketpair accepted as engine peer")
	}
	endpoint.pid++
	if err := endpoint.verifyPeer(c); err == nil {
		t.Fatal("wrong PID accepted")
	}
	endpoint.pid--
	if err := os.Rename(path, path+"-old"); err != nil {
		t.Fatal(err)
	}
	replacement, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	if err := endpoint.verifyPeer(c); err == nil {
		t.Fatal("replaced socket accepted")
	}
}
