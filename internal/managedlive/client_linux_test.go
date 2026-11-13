//go:build linux

package managedlive

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func unixPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
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
func TestSocketPeerAndTrailingData(t *testing.T) {
	a, b := unixPair(t)
	if err := peerUID(a, uint32(os.Getuid())); err != nil {
		t.Fatal(err)
	}
	if err := peerUID(a, ^uint32(0)); err == nil {
		t.Fatal("foreign peer accepted")
	}
	m := testUpdate(BankReceipt{Binding: testBinding()})
	if err := WriteFrame(b, m); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := b.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := receiveSocket(a); err == nil {
		t.Fatal("trailing bytes accepted")
	}
}
func TestReceiveOperatorAuthenticationDeadline(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("ordinary operator test requires non-root UID")
	}
	for _, late := range []bool{false, true} {
		t.Run(map[bool]string{false: "within_deadline", true: "late_auth"}[late], func(t *testing.T) {
			a, b := unixPair(t)
			binding := testBinding()
			request := &Ticket{Version: Version, Kind: "ticket", Ticket: id("1"), Credential: id("c"), Project: binding.Project, Profile: binding.Profile}
			if err := WriteFrame(b, request); err != nil {
				t.Fatal(err)
			}
			if err := b.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(250 * time.Millisecond)
			called := false
			auth := func(ctx context.Context, credential string) error {
				called = true
				d, ok := ctx.Deadline()
				if !ok || !d.Equal(deadline) || credential != request.Credential {
					t.Fatal("authentication context mismatch")
				}
				if late {
					time.Sleep(time.Until(deadline) + 20*time.Millisecond)
				}
				return nil // Even a non-cooperative authenticator may not return a late request.
			}
			got, err := receiveOperator(a, uint32(os.Getuid()), auth, binding, request.Ticket, deadline)
			if !called {
				t.Fatalf("auth not called: %v", err)
			}
			if late {
				if got != nil || !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("late authentication accepted: %v %v", got, err)
				}
			} else if err != nil || *got.(*Ticket) != *request {
				t.Fatalf("authentication failed: %v %v", got, err)
			}
		})
	}
}

func TestReceiveOperatorRejectsBeforeAuthentication(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("ordinary operator test requires non-root UID")
	}
	for _, expired := range []bool{false, true} {
		a, b := unixPair(t)
		binding := testBinding()
		request := &Ticket{Version: Version, Kind: "ticket", Ticket: id("1"), Credential: id("c"), Project: binding.Project, Profile: binding.Profile}
		if !expired {
			request.Ticket = id("2")
		}
		if err := WriteFrame(b, request); err != nil {
			t.Fatal(err)
		}
		if err := b.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(time.Second)
		if expired {
			deadline = time.Now().Add(-time.Second)
		}
		called := false
		auth := func(context.Context, string) error { called = true; return nil }
		got, err := receiveOperator(a, uint32(os.Getuid()), auth, binding, id("1"), deadline)
		if err == nil || got != nil || called {
			t.Fatalf("invalid request authenticated: %v %v %v", got, err, called)
		}
	}
}

func TestStartupStoppedTicketCorrelation(t *testing.T) {
	binding := testBinding()
	request := &Ticket{Version: Version, Kind: "ticket", Ticket: id("1"), Credential: id("c"), Project: binding.Project, Profile: binding.Profile}
	terminal := &StartupStopped{Version: Version, Kind: "startup_stopped", Ticket: request.Ticket, Binding: binding, Cleanup: "quarantined"}
	payload, err := Encode(terminal)
	if err != nil {
		t.Fatal(err)
	}
	response, err := Decode(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !matchesResponse(request, response) {
		t.Fatal("matching terminal rejected")
	}
	wrongTicket := *terminal
	wrongTicket.Ticket = id("4")
	if matchesResponse(request, &wrongTicket) {
		t.Fatal("wrong ticket accepted")
	}
	wrongProject := *terminal
	wrongProject.Binding.Project = id("5")
	if matchesResponse(request, &wrongProject) {
		t.Fatal("wrong project accepted")
	}
	wrongProfile := *terminal
	wrongProfile.Binding.Profile = "other"
	if matchesResponse(request, &wrongProfile) {
		t.Fatal("wrong profile accepted")
	}
	wrongBinding := *terminal
	wrongBinding.Binding.Session = id("6")[:32]
	if matchesResponse(request, &wrongBinding) {
		t.Fatal("invalid root binding accepted")
	}
	legacy := &Stopped{Version: Version, Kind: "stopped", Receipt: Receipt{Version: Version, RequestID: id("2"), Phase: "stopped", EngineDigest: EngineDigest, Bank: BankReceipt{Binding: binding}}, Cleanup: "clean"}
	if matchesResponse(request, legacy) {
		t.Fatal("uncorrelated terminal accepted")
	}
	statusRequest := &StatusRequest{Version: Version, Kind: "status", Credential: id("c"), Binding: binding}
	if matchesResponse(statusRequest, terminal) {
		t.Fatal("startup terminal accepted for status")
	}
	if !matchesResponse(statusRequest, legacy) {
		t.Fatal("bound stopped status rejected")
	}
	wrongSession := *legacy
	wrongSession.Receipt.Bank.Binding.Session = id("6")
	if matchesResponse(statusRequest, &wrongSession) {
		t.Fatal("wrong root session accepted after binding")
	}
}

func TestSocketRejectsAncillaryFD(t *testing.T) {
	a, b := unixPair(t)
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	payload, err := Encode(testUpdate(BankReceipt{Binding: testBinding()}))
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	copy(frame[4:], payload)
	if _, _, err = b.WriteMsgUnix(frame, unix.UnixRights(int(f.Fd())), nil); err != nil {
		t.Fatal(err)
	}
	if err = b.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err = receiveSocket(a); err == nil {
		t.Fatal("passed descriptor accepted")
	}
}
