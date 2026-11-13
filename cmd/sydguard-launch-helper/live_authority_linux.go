//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/managedlaunch"
	"github.com/Gobd/syd-guard/internal/managedstore"
	"github.com/Gobd/syd-guard/internal/syd"
	"golang.org/x/sys/unix"
)

const liveEngineDigest = "523122c5dcc5f3b65b68b58fd642086d80aaa76c5c2e9825efc47b1750c69d01"

// checkLiveEngine hashes the held, independently validated executable without
// changing its shared file offset. The same descriptor must be used for bind.
func checkLiveEngine(file *os.File, identity unix.Stat_t, owner uint32) error {
	if err := validateEngineFD(file, identity, owner); err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(file, 0, identity.Size)); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != liveEngineDigest {
		return errors.New("live engine digest mismatch")
	}
	return nil
}

// liveAuthority owns these resources only for a future live launch. No child
// receives them. The existing one-shot launch continues to close its resources.
type liveAuthority struct {
	store           *managedstore.Store
	credential      []byte
	projectID, name string
	original        *managedstore.PinnedSnapshot
	engine          *os.File
	ledger          *syd.BankLedger
}

// newLiveAuthority transfers ownership only on success. The caller must retain
// this object in ROOT and bind a.engine, never reopen the executable by path.
func newLiveAuthority(store *managedstore.Store, credential string, original *managedstore.PinnedSnapshot, engine *os.File, binding syd.BankBinding, workdir, temporary, socket string, protected []string, requirePIE bool, uid uint32) (*liveAuthority, error) {
	if store == nil || original == nil || original.Project == nil || original.Policy == nil || engine == nil || credential == "" {
		return nil, errors.New("missing live authority")
	}
	var identity unix.Stat_t
	if err := unix.Fstat(int(engine.Fd()), &identity); err != nil {
		return nil, err
	}
	if err := checkLiveEngine(engine, identity, 0); err != nil {
		return nil, err
	}
	// Verify the original selection against authenticated generation handles.
	initial, err := store.OpenPinnedSnapshot(credential, binding.Project, binding.Profile, original.Revision)
	if err != nil {
		return nil, err
	}
	defer func() { _ = initial.Close() }()
	if err := samePinnedDirectory(original.Project, initial.Project); err != nil {
		return nil, err
	}
	if err := samePinnedDirectory(original.Policy, initial.Policy); err != nil {
		return nil, err
	}
	if !bytes.Equal(original.Profile, initial.Profile) {
		return nil, errors.New("initial snapshot changed")
	}
	parsed, err := config.ParseManagedProfileSnapshot(binding.Profile, initial.Profile)
	if err != nil {
		return nil, err
	}
	if _, err := managedlaunch.ValidateIntent(parsed.Profile()); err != nil {
		return nil, err
	}
	if err := validateProjectPaths(initial.Project, parsed.Profile()); err != nil {
		return nil, err
	}
	// Even initially read-only intent can later consume the whole writable ceiling.
	ceiling := liveWritableCeiling()
	if err := validateProjectPaths(original.Project, ceiling); err != nil {
		return nil, err
	}
	if err := validateWritableSource(original.Project, ceiling, uid); err != nil {
		return nil, fmt.Errorf("live whole-project ceiling: %w", err)
	}
	// The compiler startup string alone is not safe live startup: it lacks
	// the writable Landlock ceiling and ROOT-only engine IPC authentication.
	ledger, _, err := syd.NewBankLedger(binding, liveEngineDigest, workdir, temporary, socket, protected, requirePIE)
	if err != nil {
		return nil, err
	}
	return &liveAuthority{store: store, credential: []byte(credential), projectID: binding.Project, name: binding.Profile, original: original, engine: engine, ledger: ledger}, nil
}

func liveWritableCeiling() config.Profile {
	return config.Profile{Files: []config.FileRule{{Path: ".", Access: []string{"read", "write", "delete"}, Recursive: true}}}
}

func samePinnedDirectory(a, b *os.File) error {
	var x, y unix.Stat_t
	if a == nil || b == nil {
		return errors.New("missing pinned directory")
	}
	if err := unix.Fstat(int(a.Fd()), &x); err != nil {
		return err
	}
	if err := unix.Fstat(int(b.Fd()), &y); err != nil {
		return err
	}
	if x.Mode&unix.S_IFMT != unix.S_IFDIR || y.Mode&unix.S_IFMT != unix.S_IFDIR || x.Dev != y.Dev || x.Ino != y.Ino {
		return errors.New("pinned directory identity changed")
	}
	return nil
}

// prepareSaved reads only the exact saved revision through generation-bearing
// store handles and compares both reopened objects with the launch pins.
func (a *liveAuthority) prepareSaved(ctx context.Context, revision string, predecessor syd.BankReceipt) (syd.BankBatch, error) {
	snapshot, err := a.store.OpenPinnedSnapshotContext(ctx, string(a.credential), a.projectID, a.name, revision)
	if err != nil {
		return syd.BankBatch{}, err
	}
	defer func() { _ = snapshot.Close() }()
	if err := samePinnedDirectory(a.original.Project, snapshot.Project); err != nil {
		return syd.BankBatch{}, err
	}
	if err := samePinnedDirectory(a.original.Policy, snapshot.Policy); err != nil {
		return syd.BankBatch{}, err
	}
	parsed, err := config.ParseManagedProfileSnapshot(a.name, snapshot.Profile)
	if err != nil {
		return syd.BankBatch{}, err
	}
	if _, err := managedlaunch.ValidateIntent(parsed.Profile()); err != nil {
		return syd.BankBatch{}, err
	}
	if err := validateProjectPaths(snapshot.Project, parsed.Profile()); err != nil {
		return syd.BankBatch{}, err
	}
	if err := ctx.Err(); err != nil {
		return syd.BankBatch{}, err
	}
	batch, err := a.ledger.Prepare(predecessor, snapshot.Profile)
	if err != nil {
		return syd.BankBatch{}, err
	}
	if err := ctx.Err(); err != nil {
		a.ledger.Stop()
		return syd.BankBatch{}, err
	}
	return batch, nil
}

func (a *liveAuthority) Close() error {
	clear(a.credential)
	a.credential = nil
	return errors.Join(a.original.Close(), a.engine.Close(), a.store.Close())
}
