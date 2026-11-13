//go:build linux

package managedstore

import (
	"context"
	"errors"
	"os"

	"github.com/Gobd/syd-guard/internal/config"
	"golang.org/x/sys/unix"
)

// PinnedSnapshot holds the original registered directory objects and exact
// reviewed bytes. It is a privileged setup primitive, not a launch boundary:
// a launcher must attach both directories to a private mount view before drop.
type PinnedSnapshot struct {
	Project  *os.File
	Policy   *os.File
	Revision string
	Profile  []byte
}

func (p *PinnedSnapshot) Close() error {
	return errors.Join(p.Project.Close(), p.Policy.Close())
}

// OpenPinnedSnapshot authenticates, checks the expected revision and acquires
// both held directory objects in the same store transaction. Legacy records,
// unsupported handles and stale objects are rejected; paths are never reopened.
func (s *Store) OpenPinnedSnapshot(credential, projectID, name, expected string) (*PinnedSnapshot, error) {
	return s.openPinnedSnapshot(nil, credential, projectID, name, expected)
}

// OpenPinnedSnapshotContext bounds lock waiting and rejects late snapshots;
// synchronous filesystem calls remain subject to independent watchdog fail-stop.
func (s *Store) OpenPinnedSnapshotContext(ctx context.Context, credential, projectID, name, expected string) (*PinnedSnapshot, error) {
	if ctx == nil {
		return nil, errors.New("snapshot context required")
	}
	return s.openPinnedSnapshot(ctx, credential, projectID, name, expected)
}

func (s *Store) openPinnedSnapshot(ctx context.Context, credential, projectID, name, expected string) (*PinnedSnapshot, error) {
	if !validProjectID(projectID) || config.ProfileName(name) != nil || !validProjectID(expected) {
		return nil, errors.New("invalid pinned snapshot selection")
	}
	var lock *os.File
	var err error
	if ctx == nil {
		lock, err = s.transaction(credential, false)
	} else {
		lock, err = s.transactionContext(ctx, credential)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = lock.Close() }()
	reg, err := s.lookup(projectID)
	if err != nil {
		return nil, err
	}
	projectFD, err := openDirectoryHandle(int(s.root.Fd()), reg.ProjectHandle, reg.ProjectDev, reg.ProjectIno)
	if err != nil {
		return nil, err
	}
	project := os.NewFile(uintptr(projectFD), "pinned-project")
	defer func() {
		if project != nil {
			_ = project.Close()
		}
	}()
	policyFD, err := openDirectoryHandle(int(s.root.Fd()), reg.PolicyHandle, reg.PolicyDev, reg.PolicyIno)
	if err != nil {
		return nil, err
	}
	policy := os.NewFile(uintptr(policyFD), "pinned-policy")
	defer func() {
		if policy != nil {
			_ = policy.Close()
		}
	}()
	var p, d, root unix.Stat_t
	if err := unix.Fstat(projectFD, &p); err != nil {
		return nil, err
	}
	if err := unix.Fstat(policyFD, &d); err != nil {
		return nil, err
	}
	if err := unix.Fstat(int(s.root.Fd()), &root); err != nil {
		return nil, err
	}
	if p.Dev != root.Dev || d.Dev != root.Dev || int(p.Uid) != s.uid || p.Mode&0o022 != 0 || d.Uid != 0 || d.Mode&0o7777 != 0o755 {
		return nil, errors.New("pinned directory ownership or filesystem changed")
	}
	data, err := readAt(policyFD, name+".json", Limit, 0o644)
	if err != nil {
		return nil, err
	}
	snapshot, err := config.ParseManagedProfileSnapshot(name, data)
	if err != nil {
		return nil, err
	}
	if snapshot.Revision() != expected {
		return nil, ErrConflict
	}
	if ctx != nil {
		if err := authenticationContextErr(ctx); err != nil {
			return nil, err
		}
	}
	result := &PinnedSnapshot{Project: project, Policy: policy, Revision: snapshot.Revision(), Profile: snapshot.Bytes()}
	project, policy = nil, nil
	return result, nil
}
