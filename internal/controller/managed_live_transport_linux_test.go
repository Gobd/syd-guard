//go:build linux

package controller

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestManagedLiveTransportCancelsDialAndRejectsOrdinaryPeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	started := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		_, err := exchangeManagedLive(ctx, func(ctx context.Context) (*net.UnixConn, error) { close(started); <-ctx.Done(); return nil, ctx.Err() }, nil)
		result <- err
	}()
	<-started
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("dial not joined")
	}
	if os.Getuid() == 0 {
		t.Skip("ordinary peer requires non-root UID")
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	toConn := func(fd int) *net.UnixConn {
		f := os.NewFile(uintptr(fd), "socket")
		c, err := net.FileConn(f)
		_ = f.Close()
		if err != nil {
			t.Fatal(err)
		}
		return c.(*net.UnixConn)
	}
	a, b := toConn(pair[0]), toConn(pair[1])
	defer b.Close()
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = exchangeManagedLive(ctx, func(context.Context) (*net.UnixConn, error) { return a, nil }, nil)
	if err == nil {
		t.Fatal("ordinary peer accepted as ROOT")
	}
	_ = b.SetReadDeadline(time.Now().Add(time.Second))
	var data [1]byte
	n, err := b.Read(data[:])
	if n != 0 || err != io.EOF {
		t.Fatalf("request sent before peer authentication: %d %v", n, err)
	}
}
