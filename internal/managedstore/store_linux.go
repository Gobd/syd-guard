//go:build linux

// Package managedstore implements bounded, root-owned project policy storage.
// It does not grant sandbox permissions. Callers must review snapshots and keep
// the helper's credential and channel inaccessible to workloads.
package managedstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Gobd/syd-guard/internal/config"
	"golang.org/x/sys/unix"
)

type registration struct {
	Project       string           `json:"project"`
	ProjectDev    uint64           `json:"project_dev"`
	ProjectIno    uint64           `json:"project_ino"`
	PolicyDev     uint64           `json:"policy_dev"`
	PolicyIno     uint64           `json:"policy_ino"`
	ProjectHandle *directoryHandle `json:"project_handle,omitempty"`
	PolicyHandle  *directoryHandle `json:"policy_handle,omitempty"`
}

// Store must be opened by the dedicated installed helper, never by an agent.
// Root is trusted installation configuration, NOT a field in the RPC request.
type Store struct {
	root *os.File
	uid  int
}

func Open(root string, uid int) (*Store, error) {
	if os.Geteuid() != 0 || uid <= 0 {
		return nil, fmt.Errorf("root helper and non-root operator UID required")
	}
	fd, err := openDirectory(root)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), root)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = f.Close()
		return nil, err
	}
	if stat.Uid != 0 || stat.Mode&0o7777 != 0o700 {
		_ = f.Close()
		return nil, fmt.Errorf("helper registry must be root-owned mode 0700")
	}
	if err := localFilesystem(fd); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Store{root: f, uid: uid}, nil
}
func (s *Store) Close() error { return s.root.Close() }

// Bootstrap is an explicit administrator operation. It accepts only a private,
// operator-owned, single-link credential file, and never replaces an existing
// enrollment. No credential or credential-file path is accepted by normal RPC.
func (s *Store) Bootstrap(credentialFile string) error {
	fd, err := openRegular(credentialFile)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), credentialFile)
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if !st.Mode().IsRegular() || int(stat.Uid) != s.uid || stat.Nlink != 1 || stat.Mode&0o7777 != 0o600 {
		return fmt.Errorf("credential must be operator-owned mode 0600 with one link")
	}
	b, err := io.ReadAll(io.LimitReader(f, 129))
	if err != nil {
		return err
	}
	value := string(b)
	if !validCredential(value) {
		return fmt.Errorf("credential must be 32 random bytes encoded as hex")
	}
	// Enrollment establishes the lock before the credential becomes usable, so a
	// catalog never creates registry files. Older enrollments without this lock
	// fail closed until an ordinary mutating transaction creates it.
	fdLock, err := openTransactionLock(int(s.root.Fd()), true)
	if err != nil {
		return err
	}
	lock := os.NewFile(uintptr(fdLock), "transactions.lock")
	if err := checkRootFile(lock, 0o600); err != nil {
		_ = lock.Close()
		return err
	}
	if err := lock.Close(); err != nil {
		return err
	}
	if err := unix.Fsync(int(s.root.Fd())); err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(value))
	return s.create(strconv.Itoa(s.uid)+".credential", []byte(hex.EncodeToString(digest[:])), 0o600)
}

func validCredential(v string) bool {
	if len(v) != 64 {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil
}

// openAuthenticatedLock verifies the credential and opens the fixed lock inode.
func (s *Store) openAuthenticatedLock(credential string, createLock bool) (*os.File, error) {
	if !validCredential(credential) {
		return nil, fmt.Errorf("operator credential required")
	}
	enrolled, err := s.read(strconv.Itoa(s.uid)+".credential", 128, 0o600)
	if err != nil {
		return nil, fmt.Errorf("operator is not enrolled")
	}
	digest := sha256.Sum256([]byte(credential))
	if subtle.ConstantTimeCompare(enrolled, []byte(hex.EncodeToString(digest[:]))) != 1 {
		return nil, fmt.Errorf("operator credential rejected")
	}
	fd, err := openTransactionLock(int(s.root.Fd()), createLock)
	if err != nil {
		return nil, err
	}
	lock := os.NewFile(uintptr(fd), "transactions.lock")
	if err := checkRootFile(lock, 0o600); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return lock, nil
}

// transaction retains the existing five-second behavior for non-live operations.
func (s *Store) transaction(credential string, createLock bool) (*os.File, error) {
	lock, err := s.openAuthenticatedLock(credential, createLock)
	if err != nil {
		return nil, err
	}
	fd := int(lock.Fd())
	deadline := time.Now().Add(5 * time.Second)
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) || time.Now().After(deadline) {
			_ = lock.Close()
			return nil, fmt.Errorf("lock unavailable: %w", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	return lock, nil
}

// Authenticate confirms the enrolled operator credential without mutating the
// registry. Privileged consumers may use it before allocating bounded resources;
// they must authenticate again when opening the selected snapshot transaction.
func (s *Store) Authenticate(credential string) error {
	lock, err := s.transaction(credential, false)
	if err != nil {
		return err
	}
	return lock.Close()
}

// AuthenticateContext authenticates without mutation, using the caller's
// deadline (and at most the normal five-second lock budget). Filesystem calls
// themselves are synchronous; the context bounds lock waiting, not a stuck FS.
func (s *Store) AuthenticateContext(ctx context.Context, credential string) error {
	if ctx == nil {
		return errors.New("authentication context required")
	}
	lock, err := s.transactionContext(ctx, credential)
	if err != nil {
		return err
	}
	if err := lock.Close(); err != nil {
		return err
	}
	return authenticationContextErr(ctx)
}

func (s *Store) transactionContext(ctx context.Context, credential string) (*os.File, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := authenticationContextErr(ctx); err != nil {
		return nil, err
	}
	lock, err := s.openAuthenticatedLock(credential, false)
	if err != nil {
		return nil, err
	}
	if err := lockWithContext(ctx, int(lock.Fd())); err != nil {
		_ = lock.Close()
		return nil, err
	}
	if err := authenticationContextErr(ctx); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return lock, nil
}

func authenticationContextErr(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func lockWithContext(ctx context.Context, fd int) error {
	for {
		if err := authenticationContextErr(ctx); err != nil {
			return err
		}
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return authenticationContextErr(ctx)
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			return fmt.Errorf("lock unavailable: %w", err)
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (s *Store) Apply(r Request) (result Response, resultErr error) {
	if r.Operation != "register" && r.Operation != "catalog" && config.ProfileName(r.Name) != nil {
		return Response{}, fmt.Errorf("invalid profile name")
	}
	lock, err := s.transaction(r.Credential, r.Operation != "catalog")
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = lock.Close() }()
	if r.Operation == "register" {
		return s.register(r)
	}
	if r.Operation == "catalog" {
		return s.catalog()
	}
	reg, err := s.lookup(r.Project)
	if err != nil {
		return Response{}, err
	}
	project, err := openDirectory(reg.Project)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = unix.Close(project) }()
	var st unix.Stat_t
	if err := unix.Fstat(project, &st); err != nil {
		return Response{}, err
	}
	if st.Dev != reg.ProjectDev || st.Ino != reg.ProjectIno || int(st.Uid) != s.uid || st.Mode&0o022 != 0 {
		return Response{}, fmt.Errorf("registered project identity changed")
	}
	policy, err := unix.Openat(project, config.ProfileFolder, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = unix.Close(policy) }()
	if err := unix.Fstat(policy, &st); err != nil {
		return Response{}, err
	}
	if st.Dev != reg.PolicyDev || st.Ino != reg.PolicyIno || st.Uid != 0 || st.Mode&0o7777 != 0o755 {
		return Response{}, fmt.Errorf("managed policy directory identity/ownership changed")
	}
	// This narrows in-flight rename races; it cannot make the pathname immutable.
	defer func() {
		if err := checkRegistrationIdentity(reg); err != nil {
			result = Response{}
			if r.Operation == "create" || r.Operation == "replace" {
				resultErr = fmt.Errorf("%w: namespace changed", ErrIndeterminate)
			} else {
				resultErr = err
			}
		}
	}()
	filename := r.Name + ".json"
	switch r.Operation {
	case "create":
		if len(r.Profile) != 0 || r.Expected != "" {
			return Response{}, fmt.Errorf("create accepts only a new empty profile")
		}
		data, _ := json.Marshal(config.Profile{Version: 1, Name: r.Name, Files: []config.FileRule{}, Network: []config.NetworkRule{}})
		if err := createAt(policy, filename, data, 0o644); err != nil {
			return Response{}, err
		}
		return response(r, reg, data)
	case "read", "replace":
		data, err := readAt(policy, filename, Limit, 0o644)
		if err != nil {
			return Response{}, err
		}
		old, err := config.ParseManagedProfileSnapshot(r.Name, data)
		if err != nil {
			return Response{}, err
		}
		if r.Operation == "read" {
			if len(r.Profile) != 0 || r.Expected != "" {
				return Response{}, fmt.Errorf("read accepts no write fields")
			}
			return snapshotResponse(r, reg, old.Revision(), old.Bytes()), nil
		}
		if r.Expected == "" || r.Expected != old.Revision() {
			return Response{}, ErrConflict
		}
		next, err := config.ParseManagedProfileSnapshot(r.Name, r.Profile)
		if err != nil {
			return Response{}, err
		}
		if err := replaceAt(policy, filename, next.Bytes()); err != nil {
			return Response{}, err
		}
		return snapshotResponse(r, reg, next.Revision(), next.Bytes()), nil
	default:
		return Response{}, fmt.Errorf("unsupported managed-policy operation")
	}
}

var ErrUnsupportedFilesystem = errors.New("project and registry require the same ext4/tmpfs device; backing-storage locality requires administrator verification")

func (s *Store) key(project string) string {
	return "project-" + strconv.Itoa(s.uid) + "-" + project + ".json"
}

func (s *Store) lookup(project string) (registration, error) {
	var result registration
	if !validCredential(project) {
		return result, fmt.Errorf("invalid project registration ID")
	}
	data, err := s.read(s.key(project), 8192, 0o600)
	if err != nil {
		return result, fmt.Errorf("project is not registered")
	}
	return parseRegistration(data)
}

func parseRegistration(data []byte) (registration, error) {
	var result registration
	fields, err := strictObject(data, "project", "project_dev", "project_ino", "policy_dev", "policy_ino", "project_handle", "policy_handle")
	if err != nil {
		return result, errors.New("invalid registration")
	}
	required := []string{"project", "project_dev", "project_ino", "policy_dev", "policy_ino"}
	_, hasProjectHandle := fields["project_handle"]
	_, hasPolicyHandle := fields["policy_handle"]
	if hasProjectHandle != hasPolicyHandle {
		return result, errors.New("incomplete registration handles")
	}
	if hasProjectHandle {
		required = append(required, "project_handle", "policy_handle")
		for _, name := range []string{"project_handle", "policy_handle"} {
			handleFields, err := strictObject(fields[name], "type", "data")
			if err != nil || requireFields(handleFields, "type", "data") != nil {
				return result, errors.New("invalid registration handle")
			}
		}
	}
	if requireFields(fields, required...) != nil {
		return result, errors.New("invalid registration")
	}
	if err := decodeStrict(data, &result); err != nil {
		return result, err
	}
	// Reject older registrations incompatible with the client before any create
	// or replace can publish an unreconcilable snapshot.
	if result.ProjectIno == 0 || result.PolicyIno == 0 {
		return result, errors.New("invalid registration identity")
	}
	if hasProjectHandle {
		if _, err := result.ProjectHandle.fileHandle(); err != nil {
			return result, err
		}
		if _, err := result.PolicyHandle.fileHandle(); err != nil {
			return result, err
		}
	}
	if err := ValidateProjectPath(result.Project); err != nil {
		return result, err
	}
	return result, nil
}

func (s *Store) register(r Request) (result Response, resultErr error) {
	// Validate before opening, staging or publishing anything. Registration and
	// subsequent snapshot validation must use the same path syntax boundary.
	if err := ValidateProjectPath(r.Project); err != nil {
		return Response{}, err
	}
	if r.Expected != "" || len(r.Profile) != 0 || r.Name != "" {
		return Response{}, fmt.Errorf("registration does not import/overwrite profiles")
	}
	project, err := openDirectory(r.Project)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = unix.Close(project) }()
	var st unix.Stat_t
	if err := unix.Fstat(project, &st); err != nil {
		return Response{}, err
	}
	if int(st.Uid) != s.uid || st.Mode&0o022 != 0 {
		return Response{}, fmt.Errorf("project must be operator-owned and not group/world writable")
	}
	if err := localFilesystem(project); err != nil {
		return Response{}, err
	}
	reg := registration{Project: r.Project, ProjectDev: st.Dev, ProjectIno: st.Ino}
	var registryStat unix.Stat_t
	if err := unix.Fstat(int(s.root.Fd()), &registryStat); err != nil {
		return Response{}, err
	}
	if st.Dev != registryStat.Dev {
		return Response{}, ErrUnsupportedFilesystem
	}
	reg.ProjectHandle, err = captureDirectoryHandle(int(s.root.Fd()), project)
	if err != nil {
		return Response{}, err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Response{}, err
	}
	stage := ".directory-" + hex.EncodeToString(nonce[:])
	root := int(s.root.Fd())
	if err := unix.Mkdirat(root, stage, 0o700); err != nil {
		return Response{}, err
	}
	published := false
	defer func() {
		if published {
			if resultErr == nil {
				resultErr = checkRegistrationIdentity(reg)
			}
			if resultErr != nil {
				result = Response{}
				resultErr = fmt.Errorf("%w: registration may have published", ErrIndeterminate)
			}
		}
	}()
	defer func() {
		if !published {
			_ = unix.Unlinkat(root, stage, unix.AT_REMOVEDIR)
		}
	}()
	policy, err := unix.Openat(root, stage, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = unix.Close(policy) }()
	if err := unix.Fchmod(policy, 0o755); err != nil {
		return Response{}, err
	}
	if err := unix.Fstat(policy, &st); err != nil {
		return Response{}, err
	}
	if st.Uid != 0 || st.Mode&0o7777 != 0o755 {
		return Response{}, fmt.Errorf("new policy directory failed root ownership check")
	}
	reg.PolicyDev, reg.PolicyIno = st.Dev, st.Ino
	reg.PolicyHandle, err = captureDirectoryHandle(root, policy)
	if err != nil {
		return Response{}, err
	}
	if err := unix.Fsync(policy); err != nil {
		return Response{}, err
	}
	if err := unix.Renameat2(root, stage, project, config.ProfileFolder, unix.RENAME_NOREPLACE); err != nil {
		return Response{}, fmt.Errorf("only fresh managed directories are supported; existing .sydguard is never adopted: %w", err)
	}
	published = true
	if err := unix.Fsync(root); err != nil {
		return Response{}, err
	}
	if err := unix.Fsync(project); err != nil {
		return Response{}, err
	}
	// Reopen the canonical path and policy entry before publishing the registration.
	current, err := openDirectory(r.Project)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = unix.Close(current) }()
	var projectNow, policyNow unix.Stat_t
	if err := unix.Fstat(current, &projectNow); err != nil {
		return Response{}, err
	}
	if projectNow.Dev != reg.ProjectDev || projectNow.Ino != reg.ProjectIno {
		return Response{}, fmt.Errorf("project identity changed during registration")
	}
	if err := unix.Fstatat(current, config.ProfileFolder, &policyNow, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return Response{}, err
	}
	if policyNow.Dev != reg.PolicyDev || policyNow.Ino != reg.PolicyIno || policyNow.Mode&unix.S_IFMT != unix.S_IFDIR {
		return Response{}, fmt.Errorf("policy identity changed during registration")
	}
	data, err := json.Marshal(reg)
	if err != nil {
		return Response{}, err
	}
	// If registration fails, leave the new root-owned directory for administrator
	// inspection rather than removing any path whose identity might have changed.
	var id [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		return Response{}, err
	}
	projectID := hex.EncodeToString(id[:])
	if err := unix.Fsync(project); err != nil {
		return Response{}, err
	}
	if err := s.create(s.key(projectID), data, 0o600); err != nil {
		return Response{}, err
	}
	return Response{Project: projectID}, nil
}

func response(r Request, reg registration, data []byte) (Response, error) {
	snap, err := config.ParseManagedProfileSnapshot(r.Name, data)
	if err != nil {
		return Response{}, err
	}
	return snapshotResponse(r, reg, snap.Revision(), snap.Bytes()), nil
}

func snapshotResponse(r Request, reg registration, revision string, data []byte) Response {
	return Response{
		Revision: revision, Profile: data, Project: r.Project, Name: r.Name,
		Namespace: &ProjectNamespace{Path: reg.Project, ProjectDev: reg.ProjectDev, ProjectIno: reg.ProjectIno, PolicyDev: reg.PolicyDev, PolicyIno: reg.PolicyIno},
	}
}

func decodeStrict(data []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}

func (s *Store) create(name string, data []byte, mode uint32) error {
	return createAt(int(s.root.Fd()), name, data, mode)
}

func (s *Store) read(name string, max int64, mode os.FileMode) ([]byte, error) {
	return readAt(int(s.root.Fd()), name, max, mode)
}

// Only a newly and exclusively created lock inode may have its mode corrected.
// Existing inodes retain fail-closed ownership/mode/link validation at the caller.
// Catalog opens an existing lock read-only and never creates or chmods anything.
func openTransactionLock(dir int, create bool) (int, error) {
	flags := unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
	if !create {
		return unix.Openat(dir, "transactions.lock", unix.O_RDONLY|flags, 0)
	}
	fd, err := unix.Openat(dir, "transactions.lock", unix.O_RDWR|flags|unix.O_CREAT|unix.O_EXCL, 0o600)
	if err == nil {
		if err = unix.Fchmod(fd, 0o600); err == nil {
			err = unix.Fsync(fd)
		}
		if err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
		return fd, nil
	}
	if !errors.Is(err, unix.EEXIST) {
		return -1, err
	}
	return unix.Openat(dir, "transactions.lock", unix.O_RDWR|flags, 0)
}

func checkRootFile(f *os.File, mode os.FileMode) error {
	st, err := f.Stat()
	if err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &stat); err != nil {
		return err
	}
	if !st.Mode().IsRegular() || stat.Uid != 0 || stat.Nlink != 1 || os.FileMode(stat.Mode&0o7777) != mode {
		return fmt.Errorf("invalid managed root-owned regular file")
	}
	return nil
}

func readAt(dir int, name string, max int64, mode os.FileMode) ([]byte, error) {
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer func() { _ = f.Close() }()
	if err := checkRootFile(f, mode); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("managed file too large")
	}
	return data, nil
}

// writeAt stages once in the root-owned directory. Cleanup only targets the
// inode created by this invocation; crash leftovers require admin inspection.
func writeAt(dir int, name string, data []byte, mode uint32, replace bool) error {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	stage := ".file-" + hex.EncodeToString(nonce[:])
	fd, err := unix.Openat(dir, stage, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), stage)
	defer func() { _ = f.Close() }()
	var own unix.Stat_t
	if err := unix.Fstat(fd, &own); err != nil {
		return err
	}
	defer cleanupStage(dir, stage, own)

	if err := f.Chmod(os.FileMode(mode)); err != nil {
		return err
	}
	if err := checkRootFile(f, os.FileMode(mode)); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	return publishStaged(dir, stage, name, f, replace, publicationOps{
		syncFile: func(f *os.File) error { return f.Sync() },
		rename: func(dir int, stage, name string, replace bool) error {
			if replace {
				return unix.Renameat(dir, stage, dir, name)
			}
			return unix.Renameat2(dir, stage, dir, name, unix.RENAME_NOREPLACE)
		},
		syncDir: unix.Fsync,
	})
}

// The directory is root-owned and non-writable by workloads. Identity checks
// are not an atomic defense against a privileged actor replacing the entry.
func cleanupStage(dir int, stage string, own unix.Stat_t) {
	var current unix.Stat_t
	if unix.Fstatat(dir, stage, &current, unix.AT_SYMLINK_NOFOLLOW) == nil && current.Dev == own.Dev && current.Ino == own.Ino {
		_ = unix.Unlinkat(dir, stage, 0)
	}
}

type publicationOps struct {
	syncFile func(*os.File) error
	rename   func(int, string, string, bool) error
	syncDir  func(int) error
}

func publishStaged(dir int, stage, name string, file *os.File, replace bool, ops publicationOps) error {
	if err := ops.syncFile(file); err != nil {
		return err
	}
	if err := ops.rename(dir, stage, name, replace); err != nil {
		return err
	}
	if err := ops.syncDir(dir); err != nil {
		return fmt.Errorf("%w: directory sync failed", ErrIndeterminate)
	}
	return nil
}

func createAt(dir int, name string, data []byte, mode uint32) error {
	return writeAt(dir, name, data, mode, false)
}

func replaceAt(dir int, name string, data []byte) error {
	return writeAt(dir, name, data, 0o644, true)
}

func checkRegistrationIdentity(reg registration) error {
	project, err := openDirectory(reg.Project)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(project) }()
	var p, policy unix.Stat_t
	if err := unix.Fstat(project, &p); err != nil {
		return err
	}
	if err := unix.Fstatat(project, config.ProfileFolder, &policy, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if p.Dev != reg.ProjectDev || p.Ino != reg.ProjectIno || policy.Dev != reg.PolicyDev || policy.Ino != reg.PolicyIno || policy.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("registered namespace changed")
	}
	return nil
}

// openDirectory traverses through pinned FDs with no symlinks at any component.
func openDirectory(path string) (int, error) {
	if err := ValidateProjectPath(path); err != nil {
		return -1, err
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if e != nil {
			return -1, e
		}
		fd = next
	}
	return fd, nil
}

func openRegular(path string) (int, error) {
	parent, err := openDirectory(filepath.Dir(path))
	if err != nil {
		return -1, err
	}
	defer func() { _ = unix.Close(parent) }()
	return unix.Openat(parent, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
}

func localFilesystem(fd int) error {
	var stat unix.Statfs_t
	if err := unix.Fstatfs(fd, &stat); err != nil {
		return err
	}
	// Filesystem-magic allowlist only: ext4 can have remote block/loop backing.
	// Locality needs administrator verification. Ordinary virtiofs/FUSE/network
	// filesystem types are unsupported.
	if stat.Type != unix.EXT4_SUPER_MAGIC && stat.Type != unix.TMPFS_MAGIC {
		return ErrUnsupportedFilesystem
	}
	return nil
}

// DecodeRequest rejects unknown fields, oversized bodies and additional JSON.
func DecodeRequest(reader io.Reader) (Request, error) {
	var r Request
	data, err := io.ReadAll(io.LimitReader(reader, 2*Limit+8193))
	if err != nil {
		return r, err
	}
	if len(data) > 2*Limit+8192 {
		return r, errors.New("request too large")
	}
	return decodeRequest(data)
}
