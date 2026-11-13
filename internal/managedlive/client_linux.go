//go:build linux

package managedlive

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/Gobd/syd-guard/internal/managedstore"
	"golang.org/x/sys/unix"
)

func peerUID(c *net.UnixConn, expected uint32) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var check error
	if err = raw.Control(func(fd uintptr) {
		typ, e := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TYPE)
		if e != nil || typ != unix.SOCK_STREAM {
			check = errors.New("live connection is not a stream")
			return
		}
		peer, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if e != nil || peer.Uid != expected {
			check = errors.New("live peer UID mismatch")
		}
	}); err != nil {
		return err
	}
	return check
}

// readSocket detects and closes unexpected passed descriptors before rejection.
func readSocket(c *net.UnixConn, b []byte) (int, error) {
	oob := make([]byte, unix.CmsgSpace(4*64))
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var n, on, flags int
	var recvErr error
	err = raw.Read(func(fd uintptr) bool {
		n, on, flags, _, recvErr = unix.Recvmsg(int(fd), b, oob, unix.MSG_CMSG_CLOEXEC|unix.MSG_DONTWAIT)
		return recvErr != unix.EAGAIN && recvErr != unix.EINTR
	})
	if err != nil {
		return 0, err
	}
	if on > 0 {
		msgs, _ := unix.ParseSocketControlMessage(oob[:on])
		for _, m := range msgs {
			fds, e := unix.ParseUnixRights(&m)
			if e == nil {
				for _, fd := range fds {
					_ = unix.Close(fd)
				}
			}
		}
	}
	if on != 0 || flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 {
		return 0, errors.New("unexpected ancillary data")
	}
	if recvErr != nil {
		return 0, recvErr
	}
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}
func readSocketFull(c *net.UnixConn, b []byte) error {
	for len(b) > 0 {
		n, err := readSocket(c, b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		b = b[n:]
	}
	return nil
}
func receiveSocket(c *net.UnixConn) (any, error) {
	var h [4]byte
	if err := readSocketFull(c, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > MaxFrame {
		return nil, errors.New("invalid live frame length")
	}
	b := make([]byte, n)
	if err := readSocketFull(c, b); err != nil {
		return nil, err
	}
	// One frame per half-closed connection; this also rejects trailing bytes.
	var extra [1]byte
	count, err := readSocket(c, extra[:])
	if count != 0 || err != io.EOF {
		return nil, errors.New("trailing or unterminated live frame")
	}
	return Decode(b)
}

// Exchange uses a direct Unix stream connection, authenticates ROOT's actual
// peer UID, and accepts only a response bound to the submitted selection.
// It does not discover or activate sessions; caller owns and closes the socket.
func Exchange(c *net.UnixConn, request any, deadline time.Time) (any, error) {
	if deadline.IsZero() {
		return nil, errors.New("absolute deadline required")
	}
	if err := c.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if err := peerUID(c, 0); err != nil {
		return nil, err
	}
	if err := WriteFrame(c, request); err != nil {
		return nil, err
	}
	if err := c.CloseWrite(); err != nil {
		return nil, err
	}
	response, err := receiveSocket(c)
	if err != nil {
		return nil, err
	}
	if !matchesResponse(request, response) {
		return nil, errors.New("live response binding mismatch")
	}
	return response, nil
}

// ReceiveOperator authenticates an ordinary operator and the managed-store
// credential before returning a typed request. Rejecting malformed or foreign
// connections must never by itself stop the session.
func ReceiveOperator(c *net.UnixConn, uid uint32, store *managedstore.Store, binding Binding, ticket string, deadline time.Time) (any, error) {
	if store == nil {
		return nil, errors.New("invalid operator authentication context")
	}
	return receiveOperator(c, uid, store.AuthenticateContext, binding, ticket, deadline)
}

func receiveOperator(c *net.UnixConn, uid uint32, authenticate func(context.Context, string) error, binding Binding, ticket string, deadline time.Time) (any, error) {
	if c == nil || authenticate == nil || uid == 0 || !binding.valid() || !hexID(ticket) || deadline.IsZero() {
		return nil, errors.New("invalid operator authentication context")
	}
	if err := c.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if err := peerUID(c, uid); err != nil {
		return nil, err
	}
	v, err := receiveSocket(c)
	if err != nil {
		return nil, err
	}
	var credential string
	switch m := v.(type) {
	case *Ticket:
		if m.Ticket != ticket || m.Project != binding.Project || m.Profile != binding.Profile {
			return nil, errors.New("ticket mismatch")
		}
		credential = m.Credential
	case *Release:
		if m.Ready.Bank.Binding != binding {
			return nil, errors.New("binding mismatch")
		}
		credential = m.Credential
	case *ApplySaved:
		if m.Binding != binding {
			return nil, errors.New("binding mismatch")
		}
		credential = m.Credential
	case *StatusRequest:
		if m.Binding != binding {
			return nil, errors.New("binding mismatch")
		}
		credential = m.Credential
	default:
		return nil, errors.New("not an operator request")
	}
	if !time.Now().Before(deadline) {
		return nil, context.DeadlineExceeded
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	if err := authenticate(ctx, credential); err != nil {
		return nil, err
	}
	if !time.Now().Before(deadline) || ctx.Err() != nil {
		return nil, context.DeadlineExceeded
	}
	return v, nil
}

func matchesResponse(request, response any) bool {
	if validate(request) != nil || validate(response) != nil {
		return false
	}
	var binding Binding
	switch r := request.(type) {
	case *Ticket:
	case *Release:
		binding = r.Ready.Bank.Binding
	case *ApplySaved:
		binding = r.Binding
	case *StatusRequest:
		binding = r.Binding
	default:
		return false
	}
	var receipt Receipt
	switch r := response.(type) {
	case *Ready:
		receipt = r.Receipt
		ticket, ok := request.(*Ticket)
		if !ok || r.Ticket != ticket.Ticket || receipt.Bank.Binding.Project != ticket.Project || receipt.Bank.Binding.Profile != ticket.Profile {
			return false
		}
		binding = receipt.Bank.Binding
	case *Applied:
		receipt = r.Receipt
		update, ok := request.(*ApplySaved)
		if !ok || receipt.RequestID != update.RequestID || receipt.Bank.Sequence != update.Sequence || receipt.Bank.Revision != update.Revision {
			return false
		}
	case *Status:
		receipt = r.Receipt
		switch q := request.(type) {
		case *StatusRequest:
		case *Release:
			if receipt != q.Ready {
				return false
			}
		default:
			return false
		}
	case *Stopped:
		receipt = r.Receipt
		if q, ok := request.(*ApplySaved); ok && receipt.RequestID != q.RequestID {
			return false
		}
	case *StartupStopped:
		ticket, ok := request.(*Ticket)
		return ok && r.Ticket == ticket.Ticket && r.Binding.Project == ticket.Project && r.Binding.Profile == ticket.Profile
	default:
		return false
	}
	return receipt.Bank.Binding == binding
}
