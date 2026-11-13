//go:build linux

package netlink

import (
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func TestClosedPrivateHandleRetainsSockets(t *testing.T) {
	h, err := NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	socket := h.sockets[unix.NETLINK_ROUTE]
	h.Close()
	if h.sockets[unix.NETLINK_ROUTE] != socket || h.newNetlinkRequest(unix.RTM_GETLINK, 0).Sockets == nil {
		t.Fatal("private socket map lost on close")
	}
	if _, err := h.LinkByIndex(1); err == nil {
		t.Fatal("closed handle unexpectedly succeeded")
	}
	h.Close()
}

func TestCloseConcurrentPrivateRequestConstruction(t *testing.T) {
	h, err := NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			h.Close()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			if h.newNetlinkRequest(unix.RTM_GETLINK, 0).Sockets == nil {
				t.Error("lost private map")
				return
			}
		}
	}()
	wg.Wait()
}
