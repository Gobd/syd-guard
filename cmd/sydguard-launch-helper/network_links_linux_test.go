//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	rtnl "github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type routeTestSocket struct {
	closed  chan struct{}
	entered chan string
	once    sync.Once
}

func newRouteTestSocket() *routeTestSocket {
	return &routeTestSocket{closed: make(chan struct{}), entered: make(chan string, 8)}
}
func (s *routeTestSocket) Close()                               { s.once.Do(func() { close(s.closed) }) }
func (s *routeTestSocket) block(op string) error                { s.entered <- op; <-s.closed; return os.ErrClosed }
func (s *routeTestSocket) LinkByName(string) (rtnl.Link, error) { return nil, s.block("name") }
func (s *routeTestSocket) LinkByIndex(int) (rtnl.Link, error)   { return nil, s.block("index") }
func (s *routeTestSocket) LinkAdd(rtnl.Link) error              { return s.block("add") }
func (s *routeTestSocket) LinkDel(rtnl.Link) error              { return s.block("del") }
func (s *routeTestSocket) AddrAdd(rtnl.Link, *rtnl.Addr) error  { return s.block("addr") }
func (s *routeTestSocket) RouteAdd(*rtnl.Route) error           { return s.block("route") }
func (s *routeTestSocket) LinkSetUp(rtnl.Link) error            { return s.block("up") }

func TestManagedRouteCancellationInterruptsOperations(t *testing.T) {
	for _, op := range []string{"name", "index", "add", "del", "addr", "route", "up"} {
		t.Run(op, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			s := newRouteTestSocket()
			r := newManagedRoute(ctx, s)
			defer r.Close()
			done := make(chan error, 1)
			go func() {
				switch op {
				case "name":
					_, err := r.LinkByName("x")
					done <- err
				case "index":
					_, err := r.LinkByIndex(1)
					done <- err
				case "add":
					done <- r.LinkAdd(nil)
				case "del":
					done <- r.LinkDel(nil)
				case "addr":
					done <- r.AddrAdd(nil, nil)
				case "route":
					done <- r.RouteAdd(nil)
				case "up":
					done <- r.LinkSetUp(nil)
				}
			}()
			select {
			case <-s.entered:
			case <-time.After(time.Second):
				t.Fatal("operation did not block")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("got %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation did not interrupt operation")
			}
			if err := r.LinkAdd(nil); !errors.Is(err, context.Canceled) {
				t.Fatalf("operation after cancel: %v", err)
			}
			select {
			case v := <-s.entered:
				t.Fatalf("operation reached closed socket: %s", v)
			default:
			}
		})
	}
}

type routeFirstLookupSocket struct{ *routeTestSocket }

func (s *routeFirstLookupSocket) LinkByName(string) (rtnl.Link, error) {
	time.Sleep(400 * time.Millisecond)
	return nil, nil
}

func TestManagedRouteAbsoluteTransactionDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	s := &routeFirstLookupSocket{newRouteTestSocket()}
	r := newManagedRoute(ctx, s)
	defer r.Close()
	// A completed earlier lookup consumes most of the one absolute budget.
	if _, err := r.LinkByName("first"); err != nil {
		t.Fatal(err)
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("missing original transaction deadline")
	}
	_, err := r.LinkByIndex(1)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	// The first call consumed 400ms. A fresh one-second second-call budget
	// would finish ~400ms after this original deadline and must fail here.
	if time.Now().After(deadline.Add(200 * time.Millisecond)) {
		t.Fatal("completion exceeded original deadline plus scheduling tolerance")
	}
	if err := r.LinkDel(nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("later operation: %v", err)
	}
}

func TestOpenRouteOnDisposableThreadCancellationAndOwnership(t *testing.T) {
	fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	entered, release := make(chan struct{}), make(chan struct{})
	s := newRouteTestSocket()
	done := make(chan error, 1)
	go func() {
		_, err := openRouteOnDisposableThread(ctx, fd, func(got, kind int) error {
			if got != fd || kind != unix.CLONE_NEWNET {
				return errors.New("wrong setns arguments")
			}
			return nil
		}, func() (routeSocket, error) { close(entered); <-release; return s, nil })
		done <- err
	}()
	<-entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	close(release)
	select {
	case <-s.closed:
	case <-time.After(time.Second):
		t.Fatal("abandoned socket leaked")
	}
	deadline := time.Now().Add(time.Second)
	for {
		_, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if errors.Is(err, unix.EBADF) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("owned namespace descriptor leaked")
		}
		runtime.Gosched()
	}
}

func TestOpenRouteOnDisposableThreadNeverEntersCaller(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	caller := unix.Gettid()
	fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := newRouteTestSocket()
	r, err := openRouteOnDisposableThread(context.Background(), fd, func(_, _ int) error {
		if unix.Gettid() == caller {
			return errors.New("entered caller thread")
		}
		return nil
	}, func() (routeSocket, error) { return s, nil })
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	if unix.Gettid() != caller {
		t.Fatal("caller thread changed")
	}
}

func TestOpenRouteOnDisposableThreadEntryFailure(t *testing.T) {
	fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("injected setns failure")
	_, err = openRouteOnDisposableThread(context.Background(), fd, func(_, _ int) error { return sentinel }, func() (routeSocket, error) { t.Error("opened after failed entry"); return nil, nil })
	if !errors.Is(err, sentinel) {
		t.Fatalf("got %v", err)
	}
	// The sender may still be completing its deferred close after transfer.
	deadline := time.Now().Add(time.Second)
	for {
		_, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if errors.Is(err, unix.EBADF) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("namespace descriptor leaked")
		}
		runtime.Gosched()
	}
}

func TestDuplicateRouteNamespacePinsIdentity(t *testing.T) {
	fd, err := unix.Open("/proc/self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		t.Fatal(err)
	}
	object := networkObject{Kind: "namespace", Dev: st.Dev, Ino: st.Ino}
	dup, err := duplicateRouteNamespace(fd, object)
	unix.Close(fd)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dup)
	// Reuse the borrowed number for a different object; the owned duplicate
	// remains the namespace passed to handle construction and LinkAdd.
	replacement, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if replacement != fd {
		if err := unix.Dup3(replacement, fd, unix.O_CLOEXEC); err != nil {
			unix.Close(replacement)
			t.Fatal(err)
		}
		unix.Close(replacement)
	}
	defer unix.Close(fd)
	if dup < 3 {
		t.Fatalf("nonpositive duplicate: %d", dup)
	}
	if err := verifyNetworkNamespaceFD(dup, object); err != nil {
		t.Fatal(err)
	}
}
