//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"strconv"
	"time"

	"github.com/Gobd/syd-guard/internal/session"
	"golang.org/x/sys/unix"
)

// The server belongs to the watchdog's single owner loop. On channel failure
// it keeps any retained namespace until verified whole-cgroup kill and reverse
// cleanup; Close refuses to claim that a retained lease is absent.
type networkWatchLeaseServer struct {
	socket, peer, base            int
	slot                          *launchSlot
	initial                       slotJournal
	owner                         uint32
	retained                      *os.File
	object                        networkObject
	token                         [32]byte
	sequence                      uint64
	released, poisoned, recovered bool
	releaseAuthorized             func() error
}

func networkLeaseNonce(nonce string) ([32]byte, error) {
	var result [32]byte
	raw, err := hex.DecodeString(nonce)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != nonce {
		return result, errors.New("invalid root lease generation")
	}
	copy(result[:], raw)
	return result, nil
}
func (s *networkWatchLeaseServer) journal() (slotJournal, networkObject, error) {
	j, exists, err := readJournal(s.base, s.slot, s.owner)
	if err != nil || !exists || !sameSlotBinding(j, s.initial) || j.Network == nil || len(j.Network.Objects) == 0 {
		return slotJournal{}, networkObject{}, errors.New("root network lease journal unavailable")
	}
	return j, j.Network.Objects[0], nil
}
func (s *networkWatchLeaseServer) bindingFrame(j slotJournal, o networkObject) (networkWatchLeaseFrame, error) {
	nonce, err := networkLeaseNonce(j.Nonce)
	if err != nil {
		return networkWatchLeaseFrame{}, err
	}
	return networkWatchLeaseFrame{uid: j.UID, index: uint32(j.Index), nonce: nonce, dev: o.Dev, ino: o.Ino}, nil
}
func sameNetworkLeaseBinding(a, b networkWatchLeaseFrame) bool {
	return a.uid == b.uid && a.index == b.index && a.nonce == b.nonce && a.dev == b.dev && a.ino == b.ino
}

// Takes no borrowed descriptor ownership. The socket is a separate exclusively
// inherited ROOT channel, not authenticated by socketpair SO_PEERCRED. Caller
// must have spawned this immutable watchdog and excluded all non-ROOT FD owners.
// pidfd/start/executable checks bind its actual parent, not socketpair creator
// credentials. releaseAuthorized must be the watchdog's own verified whole-
// cgroup-kill and cleanup gate, never a caller/controller assertion. UID checks
// here do not establish the required GID 0, groups, capabilities or inherited-FD
// inventory; those remain mandatory Root spawn/integration checks. This
// constructor does not itself kill the cgroup and is not wired to the launcher.
func newRootNetworkWatchLeaseServer(socket, parent, base int, slot *launchSlot, initial slotJournal, releaseAuthorized func() error) (*networkWatchLeaseServer, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || slot == nil || slot.File == nil || releaseAuthorized == nil || validateJournal(slot, initial) != nil || initial.Phase != "ready" || initial.ParentPID != os.Getppid() {
		return nil, errors.New("invalid root watchdog lease bootstrap")
	}
	if err := verifyInstallation(); err != nil {
		return nil, err
	}
	if err := checkNetworkLeaseStream(socket); err != nil {
		return nil, err
	}
	if err := verifyPidfdPID(parent, initial.ParentPID); err != nil {
		return nil, err
	}
	identity, err := session.ProcessIdentity(initial.ParentPID)
	if err != nil || identity != initial.ParentIdentity {
		return nil, errors.New("watchdog lease parent identity changed")
	}
	if err = verifyNetworkLeaseRootCredentials(initial.ParentPID); err != nil {
		return nil, err
	}
	trusted, err := trustedPath(executable, true)
	if err != nil {
		return nil, err
	}
	var executableStat unix.Stat_t
	if err = unix.Stat("/proc/"+strconv.Itoa(initial.ParentPID)+"/exe", &executableStat); err != nil || executableStat.Dev != trusted.Dev || executableStat.Ino != trusted.Ino {
		return nil, errors.New("watchdog lease parent executable changed")
	}
	dup := func(fd int) (int, error) { return unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3) }
	sock, e := dup(socket)
	if e != nil {
		return nil, e
	}
	p, e := dup(parent)
	if e != nil {
		unix.Close(sock)
		return nil, e
	}
	b, e := dup(base)
	if e != nil {
		unix.Close(sock)
		unix.Close(p)
		return nil, e
	}
	sl, e := dup(int(slot.File.Fd()))
	if e != nil {
		unix.Close(sock)
		unix.Close(p)
		unix.Close(b)
		return nil, e
	}
	ownedSlot := &launchSlot{File: os.NewFile(uintptr(sl), "network-watch-slot"), UID: slot.UID, Index: slot.Index}
	s := &networkWatchLeaseServer{socket: sock, peer: p, base: b, slot: ownedSlot, initial: initial, owner: 0, releaseAuthorized: releaseAuthorized}
	fail := func(e error) (*networkWatchLeaseServer, error) { _ = s.Close(); return nil, e }
	var bs, held, named unix.Stat_t
	if e = unix.Fstat(b, &bs); e != nil {
		return fail(e)
	}
	if bs.Mode&unix.S_IFMT != unix.S_IFDIR || bs.Uid != 0 || bs.Mode&0022 != 0 {
		return fail(errors.New("unsafe root watchdog lease directory"))
	}
	if e = unix.Fstat(sl, &held); e != nil {
		return fail(e)
	}
	if e = unix.Fstatat(b, slotName(slot.UID, slot.Index), &named, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return fail(e)
	}
	if held.Dev != named.Dev || held.Ino != named.Ino || held.Uid != 0 || held.Mode&unix.S_IFMT != unix.S_IFREG || held.Mode&07777 != 0600 || held.Nlink != 1 {
		return fail(errors.New("invalid root watchdog slot"))
	}
	if e = unix.Flock(sl, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return fail(e)
	}
	current, exists, e := readJournal(b, ownedSlot, 0)
	if e != nil || !exists || !reflect.DeepEqual(current, initial) {
		return fail(errors.New("stale root watchdog lease bootstrap"))
	}
	if e = pollNetworkLeasePeer(p); e != nil {
		return fail(e)
	}
	return s, nil
}
func pollNetworkLeasePeer(fd int) error {
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, 0)
	if err != nil || n != 0 || fds[0].Revents != 0 {
		return errors.New("network lease peer not alive")
	}
	return nil
}
func (s *networkWatchLeaseServer) Close() error {
	if s == nil {
		return nil
	}
	if s.retained != nil {
		return errors.New("retained namespace requires authorized release; quarantining")
	}
	var errs []error
	for _, fd := range []int{s.socket, s.peer, s.base} {
		if fd >= 0 {
			errs = append(errs, unix.Close(fd))
		}
	}
	if s.slot != nil && s.slot.File != nil {
		errs = append(errs, s.slot.File.Close())
	}
	s.socket = -1
	s.peer = -1
	s.base = -1
	s.slot = nil
	if s.poisoned {
		errs = append(errs, errNetworkLeaseQuarantine)
	}
	return errors.Join(errs...)
}

// retainedFDForRecovery is usable by the authenticated watchdog cleanup after
// parent death. It never reconstructs a namespace from a pathname or journal.
func (s *networkWatchLeaseServer) retainedFDForRecovery() (namespaceLeaseResult, error) {
	if s == nil || s.releaseAuthorized == nil {
		return namespaceLeaseResult{}, errors.New("network lease cleanup is not authorized")
	}
	if err := s.releaseAuthorized(); err != nil {
		return namespaceLeaseResult{}, err
	}
	j, o, err := s.journal()
	if err != nil || s.retained == nil || s.object != o {
		return namespaceLeaseResult{}, errors.New("verified retained namespace unavailable")
	}
	if err = verifyLeaseResult(namespaceLeaseResult{leaseBinding(j), o, s.retained}, leaseBinding(j), o); err != nil {
		return namespaceLeaseResult{}, err
	}
	fd, err := duplicateRouteNamespace(int(s.retained.Fd()), o)
	if err != nil {
		return namespaceLeaseResult{}, err
	}
	return namespaceLeaseResult{Binding: leaseBinding(j), Object: o, FD: os.NewFile(uintptr(fd), "watchdog-recovery-namespace")}, nil
}

// errNetworkLeaseQuarantine distinguishes successful physical FD release from
// proof of lease transaction delivery; callers must retain the deleting journal.
var errNetworkLeaseQuarantine = errors.New("network lease cleanup outcome unconfirmed; quarantining")

// cleanupCallbacks are private to the fixed watchdog cleanup role and are valid
// only after verified cgroup kill. An ACK send is not proof of receipt, and
// client-side failure can be invisible to this server. Thus this local cleanup
// path must always preserve durable quarantine, even when s.poisoned is false.
// Normal clean completion requires the separate, exact wire RELEASE ACK path.
func (s *networkWatchLeaseServer) cleanupCallbacks() namespaceLeaseCallbacks {
	return namespaceLeaseCallbacks{
		lease: func(_ context.Context, _ namespaceLeaseBinding, _ networkObject, f *os.File) (namespaceLeaseResult, error) {
			if f != nil {
				_ = f.Close()
			}
			return namespaceLeaseResult{}, errors.New("watchdog cleanup cannot create a lease")
		},
		recover: func(ctx context.Context, b namespaceLeaseBinding, o networkObject) (namespaceLeaseResult, error) {
			if err := ctx.Err(); err != nil {
				return namespaceLeaseResult{}, err
			}
			r, err := s.retainedFDForRecovery()
			if err != nil {
				return namespaceLeaseResult{}, err
			}
			if err = verifyLeaseResult(r, b, o); err != nil {
				_ = r.FD.Close()
				return namespaceLeaseResult{}, err
			}
			if err = ctx.Err(); err != nil {
				_ = r.FD.Close()
				return namespaceLeaseResult{}, err
			}
			return r, nil
		},
		release: func(ctx context.Context, b namespaceLeaseBinding, o networkObject) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if s == nil || s.retained == nil || s.object != o || s.releaseAuthorized == nil {
				return errors.New("watchdog lease unavailable")
			}
			j, actual, err := s.journal()
			if err != nil || actual != o || leaseBinding(j) != b || j.Network.State != "deleting" || len(j.Network.Objects) != 1 {
				return errors.New("watchdog lease cleanup journal mismatch")
			}
			if err = verifyLeaseResult(namespaceLeaseResult{b, o, s.retained}, b, o); err != nil {
				return err
			}
			if err = s.releaseAuthorized(); err != nil {
				return err
			}
			if err = ctx.Err(); err != nil {
				return err
			}
			if err = s.retained.Close(); err != nil {
				return err
			}
			s.retained = nil
			s.released = true
			s.poisoned = true
			// The FD is safely closed, but no local cleanup can establish that
			// the parent received or accepted the prior lease acknowledgement.
			return errors.Join(errNetworkLeaseQuarantine, ctx.Err())
		},
	}
}

// serveNetworkLease is a dedicated-channel loop for the fixed watchdog owner.
// It returns on parent death or protocol error without dropping retained FDs;
// the caller must perform authenticated cgroup kill and identity cleanup.
func (s *networkWatchLeaseServer) serveNetworkLease(ctx context.Context) error {
	if s == nil || ctx == nil {
		return errors.New("invalid network lease loop")
	}
	for {
		if s.poisoned {
			return errNetworkLeaseQuarantine
		}
		if s.released {
			return nil
		}
		if err := pollNetworkLease(ctx, s.socket, s.peer, unix.POLLIN); err != nil {
			s.poisoned = true
			return err
		}
		if err := s.handleNetworkLease(ctx); err != nil {
			return err
		}
	}
}

// Handle one request after the owning watchdog loop observes readability.
// The original deadline is shared across the complete receive/validate/ACK.
// Any error poisons this stream; an ambiguous initial ACK is never retried.
func (s *networkWatchLeaseServer) handleNetworkLease(ctx context.Context) (err error) {
	if s == nil || s.poisoned || s.released {
		return errors.New("network lease channel unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	defer func() {
		if err != nil {
			s.poisoned = true
		}
	}()
	request, fd, err := recvNetworkWatchLeaseFrame(ctx, s.socket, s.peer, -1)
	if err != nil {
		return err
	}
	if fd >= 0 {
		defer func() {
			if fd >= 0 {
				_ = unix.Close(fd)
			}
		}()
	}
	j, o, err := s.journal()
	if err != nil {
		return err
	}
	expected, err := s.bindingFrame(j, o)
	if err != nil {
		return err
	}
	if request.role != networkWatchParent || !sameNetworkLeaseBinding(request, expected) || request.sequence != s.sequence+1 || request.sequence == 0 || request.sequence > 3 {
		return errors.New("network lease request binding or sequence mismatch")
	}
	ack := request
	ack.role = networkWatchWatchdog
	switch request.op {
	case networkWatchLease:
		if s.retained != nil || s.sequence != 0 || fd < 0 || request.retentionToken != ([32]byte{}) || j.Network.State != "recorded" || len(j.Network.Objects) != 1 {
			return errors.New("invalid initial network lease")
		}
		if err = verifyNetworkNamespaceFD(fd, o); err != nil {
			return err
		}
		flags, e := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if e != nil || flags&unix.FD_CLOEXEC == 0 {
			return errors.New("received namespace is not CLOEXEC")
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if _, err = rand.Read(s.token[:]); err != nil {
			return err
		}
		if s.token == ([32]byte{}) {
			return errors.New("invalid lease retention token")
		}
		s.retained = os.NewFile(uintptr(fd), "watchdog-retained-namespace")
		fd = -1
		s.object = o
		s.sequence = request.sequence
		ack.op = networkWatchLeaseACK
		ack.retentionToken = s.token
		return sendNetworkWatchLeaseFrame(ctx, s.socket, s.peer, ack, int(s.retained.Fd()))
	case networkWatchRecover:
		if fd >= 0 || s.retained == nil || s.object != o || request.retentionToken != s.token || s.sequence == 0 || s.recovered {
			return errors.New("unknown network recovery lease")
		}
		if err = verifyLeaseResult(namespaceLeaseResult{leaseBinding(j), o, s.retained}, leaseBinding(j), o); err != nil {
			return err
		}
		s.sequence = request.sequence
		s.recovered = true
		ack.op = networkWatchRecoverACK
		return sendNetworkWatchLeaseFrame(ctx, s.socket, s.peer, ack, int(s.retained.Fd()))
	case networkWatchRelease:
		if fd >= 0 || s.retained == nil || s.object != o || request.retentionToken != s.token || j.Network.State != "deleting" || len(j.Network.Objects) != 1 || s.releaseAuthorized == nil {
			return errors.New("network lease release not authorized")
		}
		if err = verifyLeaseResult(namespaceLeaseResult{leaseBinding(j), o, s.retained}, leaseBinding(j), o); err != nil {
			return err
		}
		if err = s.releaseAuthorized(); err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = s.retained.Close(); err != nil {
			return err
		}
		s.retained = nil
		s.sequence = request.sequence
		s.released = true
		ack.op = networkWatchReleaseACK
		return sendNetworkWatchLeaseFrame(ctx, s.socket, s.peer, ack, -1)
	default:
		return errors.New("unknown network lease operation")
	}
}
