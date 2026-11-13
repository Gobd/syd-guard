//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/Gobd/syd-guard/internal/session"
	"golang.org/x/sys/unix"
)

// The client is exclusive to the ROOT launch owner. Its pinned child comes
// from the authenticated spawn, not socketpair SO_PEERCRED. It is not installed
// in the selected launcher; callback ACKs require this actual protocol.
type networkWatchLeaseClient struct {
	socket, peer, base int
	slot               *launchSlot
	initial            slotJournal
	owner              uint32
	verifyPeer         func() error
	mu                 sync.Mutex
	sequence           uint64
	token              [32]byte
	object             networkObject
	failed, released   bool
}

func newRootNetworkWatchLeaseClient(socket, base int, slot *launchSlot, initial slotJournal, child *networkChild) (*networkWatchLeaseClient, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || slot == nil || slot.File == nil || child == nil || validateJournal(slot, initial) != nil || initial.Phase != "ready" || initial.ParentPID != os.Getpid() {
		return nil, errors.New("invalid root lease client bootstrap")
	}
	if err := verifyInstallation(); err != nil {
		return nil, err
	}
	if err := checkNetworkLeaseStream(socket); err != nil {
		return nil, err
	}
	identity, err := session.ProcessIdentity(os.Getpid())
	if err != nil || identity != initial.ParentIdentity {
		return nil, errors.New("root lease client identity changed")
	}
	trusted, err := trustedPath(executable, true)
	if err != nil {
		return nil, err
	}
	if child.executableDev != trusted.Dev || child.executableIno != trusted.Ino {
		return nil, errors.New("lease watchdog executable is not trusted")
	}
	if err = verifyNetworkLeaseChild(child); err != nil {
		return nil, err
	}
	dup := func(fd int) (int, error) { return unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3) }
	sock, err := dup(socket)
	if err != nil {
		return nil, err
	}
	peer, err := dup(child.pidfd)
	if err != nil {
		unix.Close(sock)
		return nil, err
	}
	b, err := dup(base)
	if err != nil {
		unix.Close(sock)
		unix.Close(peer)
		return nil, err
	}
	sl, err := dup(int(slot.File.Fd()))
	if err != nil {
		unix.Close(sock)
		unix.Close(peer)
		unix.Close(b)
		return nil, err
	}
	ownedSlot := &launchSlot{File: os.NewFile(uintptr(sl), "network-client-slot"), UID: slot.UID, Index: slot.Index}
	pinned := *child
	pinned.pidfd = peer
	c := &networkWatchLeaseClient{socket: sock, peer: peer, base: b, slot: ownedSlot, initial: initial, owner: 0, verifyPeer: func() error { return verifyNetworkLeaseChild(&pinned) }}
	fail := func(err error) (*networkWatchLeaseClient, error) { _ = c.Close(); return nil, err }
	var bs, held, named unix.Stat_t
	if err = unix.Fstat(b, &bs); err != nil {
		return fail(err)
	}
	if bs.Mode&unix.S_IFMT != unix.S_IFDIR || bs.Uid != 0 || bs.Mode&0022 != 0 {
		return fail(errors.New("unsafe lease client directory"))
	}
	if err = unix.Fstat(sl, &held); err != nil {
		return fail(err)
	}
	if err = unix.Fstatat(b, slotName(slot.UID, slot.Index), &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fail(err)
	}
	if held.Dev != named.Dev || held.Ino != named.Ino || held.Uid != 0 || held.Mode&unix.S_IFMT != unix.S_IFREG || held.Mode&07777 != 0600 || held.Nlink != 1 {
		return fail(errors.New("invalid root lease client slot"))
	}
	if err = unix.Flock(sl, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fail(err)
	}
	current, exists, err := readJournal(b, ownedSlot, 0)
	if err != nil || !exists || !reflect.DeepEqual(current, initial) {
		return fail(errors.New("stale root lease client journal"))
	}
	if err = verifyNetworkLeaseChild(&pinned); err != nil {
		return fail(err)
	}
	return c, nil
}
func (c *networkWatchLeaseClient) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var errs []error
	for _, fd := range []int{c.socket, c.peer, c.base} {
		if fd >= 0 {
			errs = append(errs, unix.Close(fd))
		}
	}
	if c.slot != nil && c.slot.File != nil {
		errs = append(errs, c.slot.File.Close())
	}
	c.socket = -1
	c.peer = -1
	c.base = -1
	c.slot = nil
	if c.failed || (c.sequence != 0 && !c.released) {
		errs = append(errs, errors.New("network lease outcome or release unconfirmed; quarantining"))
	}
	return errors.Join(errs...)
}
func (c *networkWatchLeaseClient) callbacks() namespaceLeaseCallbacks {
	return namespaceLeaseCallbacks{
		lease: func(ctx context.Context, b namespaceLeaseBinding, o networkObject, fd *os.File) (namespaceLeaseResult, error) {
			if fd == nil {
				return namespaceLeaseResult{}, errors.New("missing namespace lease transfer")
			}
			defer fd.Close()
			return c.exchange(ctx, networkWatchLease, b, o, fd)
		},
		recover: func(ctx context.Context, b namespaceLeaseBinding, o networkObject) (namespaceLeaseResult, error) {
			return c.exchange(ctx, networkWatchRecover, b, o, nil)
		},
		release: func(ctx context.Context, b namespaceLeaseBinding, o networkObject) error {
			_, err := c.exchange(ctx, networkWatchRelease, b, o, nil)
			return err
		},
	}
}
func (c *networkWatchLeaseClient) exchange(ctx context.Context, op byte, b namespaceLeaseBinding, o networkObject, transfer *os.File) (namespaceLeaseResult, error) {
	if c == nil || ctx == nil {
		return namespaceLeaseResult{}, errors.New("invalid lease transaction")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return namespaceLeaseResult{}, err
		}
		if c.mu.TryLock() {
			break
		}
		select {
		case <-ctx.Done():
			return namespaceLeaseResult{}, ctx.Err()
		case <-ticker.C:
		}
	}
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return namespaceLeaseResult{}, err
	}
	if c.failed || c.released || c.verifyPeer == nil || c.slot == nil || b != leaseBinding(c.initial) {
		return namespaceLeaseResult{}, errors.New("lease transaction unavailable")
	}
	if err := c.verifyPeer(); err != nil {
		return namespaceLeaseResult{}, err
	}
	j, exists, err := readJournal(c.base, c.slot, c.owner)
	if err != nil || !exists || !sameSlotBinding(j, c.initial) || j.Network == nil || len(j.Network.Objects) == 0 || j.Network.Objects[0] != o {
		return namespaceLeaseResult{}, errors.New("network lease client journal changed")
	}
	nonce, err := networkLeaseNonce(j.Nonce)
	if err != nil {
		return namespaceLeaseResult{}, err
	}
	req := networkWatchLeaseFrame{op: op, role: networkWatchParent, uid: j.UID, index: uint32(j.Index), nonce: nonce, dev: o.Dev, ino: o.Ino, sequence: c.sequence + 1, retentionToken: c.token}
	var wantFD int
	sendFD := -1
	var ack byte
	switch op {
	case networkWatchLease:
		if c.sequence != 0 || c.token != ([32]byte{}) || transfer == nil || j.Network.State != "recorded" || len(j.Network.Objects) != 1 {
			return namespaceLeaseResult{}, errors.New("invalid lease establishment")
		}
		if err = verifyLeaseResult(namespaceLeaseResult{b, o, transfer}, b, o); err != nil {
			return namespaceLeaseResult{}, err
		}
		sendFD = int(transfer.Fd())
		wantFD = 1
		ack = networkWatchLeaseACK
	case networkWatchRecover:
		if c.sequence == 0 || c.sequence >= 2 || c.token == ([32]byte{}) || c.object != o || transfer != nil {
			return namespaceLeaseResult{}, errors.New("unknown network recovery lease")
		}
		wantFD = 1
		ack = networkWatchRecoverACK
	case networkWatchRelease:
		if c.sequence == 0 || c.sequence >= 3 || c.token == ([32]byte{}) || c.object != o || transfer != nil || j.Network.State != "deleting" || len(j.Network.Objects) != 1 {
			return namespaceLeaseResult{}, errors.New("invalid lease release")
		}
		ack = networkWatchReleaseACK
	default:
		return namespaceLeaseResult{}, errors.New("invalid lease command")
	}
	// After any attempted wire operation, a failure is ambiguous and no retry is
	// permitted. In particular a lost initial ACK never establishes a new lease.
	c.failed = true
	if err = sendNetworkWatchLeaseFrame(ctx, c.socket, c.peer, req, sendFD); err != nil {
		return namespaceLeaseResult{}, err
	}
	response, fd, err := recvNetworkWatchLeaseFrame(ctx, c.socket, c.peer, wantFD)
	if err != nil {
		return namespaceLeaseResult{}, err
	}
	if fd >= 0 {
		defer func() {
			if fd >= 0 {
				_ = unix.Close(fd)
			}
		}()
	}
	expected := req
	expected.op = ack
	expected.role = networkWatchWatchdog
	if op == networkWatchLease {
		if response.retentionToken == ([32]byte{}) {
			return namespaceLeaseResult{}, errors.New("missing lease retention token")
		}
		expected.retentionToken = response.retentionToken
	}
	if response != expected {
		return namespaceLeaseResult{}, errors.New("network lease acknowledgement mismatch")
	}
	if err = c.verifyPeer(); err != nil {
		return namespaceLeaseResult{}, err
	}
	if err = ctx.Err(); err != nil {
		return namespaceLeaseResult{}, err
	}
	var result namespaceLeaseResult
	if fd >= 0 {
		file := os.NewFile(uintptr(fd), "network-watch-lease")
		fd = -1
		result = namespaceLeaseResult{Binding: b, Object: o, FD: file}
		if err = verifyLeaseResult(result, b, o); err != nil {
			file.Close()
			return namespaceLeaseResult{}, err
		}
	}
	c.sequence = req.sequence
	c.token = response.retentionToken
	c.object = o
	c.released = op == networkWatchRelease
	c.failed = false
	return result, nil
}
