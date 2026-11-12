//go:build linux

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Gobd/syd-guard/internal/config"
	"golang.org/x/sys/unix"
)

// This is the executable subset of syd.runtimeExecutablePaths. Keep it in
// sync with runtimeRules: these are fixed system paths, never request paths.
var sourceRuntimeRoots = []string{"usr", "bin", "sbin", "lib", "lib64"}

const maxSourceAncestry = 256

type directoryID struct{ dev, ino uint64 }

type ancestryOps struct {
	dup    func(int) (int, error)
	parent func(int) (int, error)
	stat   func(int) (directoryID, error)
	close  func(int) error
}

var sourceAncestryOps = ancestryOps{
	dup: func(fd int) (int, error) { return unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3) },
	parent: func(fd int) (int, error) {
		return unix.Openat(fd, "..", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	},
	stat: func(fd int) (directoryID, error) {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			return directoryID{}, err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return directoryID{}, errors.New("not a directory")
		}
		return directoryID{st.Dev, st.Ino}, nil
	},
	close: unix.Close,
}

// Walk from the pinned object to the actual namespace root. A self-parent
// anywhere else is a disconnected handle, not proof of a disjoint path.
func directoryAncestry(fd int, root directoryID, ops ancestryOps) (ids []directoryID, err error) {
	current, err := ops.dup(fd)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, ops.close(current)) }()
	seen := make(map[directoryID]bool)
	for depth := 0; depth < maxSourceAncestry; depth++ {
		id, statErr := ops.stat(current)
		if statErr != nil {
			return nil, statErr
		}
		if seen[id] {
			return nil, errors.New("directory ancestry loop or disconnected handle")
		}
		seen[id] = true
		ids = append(ids, id)
		if id == root {
			return ids, nil
		}
		next, openErr := ops.parent(current)
		if openErr != nil {
			return nil, fmt.Errorf("open directory parent: %w", openErr)
		}
		closeErr := ops.close(current)
		current = next
		if closeErr != nil {
			return nil, closeErr
		}
	}
	return nil, errors.New("directory ancestry exceeds limit")
}

func idIn(id directoryID, ids []directoryID) bool {
	for _, candidate := range ids {
		if id == candidate {
			return true
		}
	}
	return false
}

func trustedDirectory(fd int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0o022 != 0 {
		return errors.New("untrusted system directory")
	}
	return nil
}

// Fixed one-component aliases may be merged-/usr symlinks only. Every
// directory used to resolve them is checked while held by descriptor.
func openRuntimeRoot(rootFD int, name string) (int, error) {
	fd, err := unix.Openat(rootFD, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return -1, errors.Join(err, unix.Close(fd))
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		if err := unix.Close(fd); err != nil {
			return -1, err
		}
		if name == "usr" || st.Uid != 0 {
			return -1, errors.New("untrusted system alias")
		}
		buf := make([]byte, 128)
		n, readErr := unix.Readlinkat(rootFD, name, buf)
		if readErr != nil {
			return -1, readErr
		}
		target := string(buf[:n])
		if target != "usr/"+name && target != "/usr/"+name {
			return -1, errors.New("unexpected system alias target")
		}
		usr, openErr := unix.Openat(rootFD, "usr", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return -1, openErr
		}
		if err := trustedDirectory(usr); err != nil {
			return -1, errors.Join(err, unix.Close(usr))
		}
		fd, err = unix.Openat(usr, name, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		closeErr := unix.Close(usr)
		if err != nil {
			return -1, errors.Join(err, closeErr) // dangling aliases are not absent roots
		}
		if closeErr != nil {
			return -1, errors.Join(closeErr, unix.Close(fd))
		}
	}
	if err := trustedDirectory(fd); err != nil {
		return -1, errors.Join(err, unix.Close(fd))
	}
	return fd, nil
}

// Read account data from root-controlled local passwd, independent of HOME and
// NSS modules selected by the caller. Missing or ambiguous accounts fail closed.
func accountHome(rootFD int, uid uint32) (home string, err error) {
	etc, err := unix.Openat(rootFD, "etc", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, unix.Close(etc)) }()
	if err := trustedDirectory(etc); err != nil {
		return "", err
	}
	fd, err := unix.Openat(etc, "passwd", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), "passwd")
	defer func() { err = errors.Join(err, file.Close()) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return "", err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&0o022 != 0 || st.Size < 0 || st.Size > 4*1024*1024 {
		return "", errors.New("untrusted passwd")
	}
	scanner := bufio.NewScanner(io.LimitReader(file, 4*1024*1024+1))
	scanner.Buffer(make([]byte, 4096), 65536)
	found := false
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) != 7 {
			return "", errors.New("invalid passwd entry")
		}
		id, parseErr := strconv.ParseUint(fields[2], 10, 32)
		if parseErr != nil {
			return "", errors.New("invalid passwd uid")
		}
		if uint32(id) == uid {
			if found {
				return "", errors.New("ambiguous passwd uid")
			}
			found, home = true, fields[5]
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if !found || !filepath.IsAbs(home) || filepath.Clean(home) != home || home == "/" {
		return "", errors.New("invalid account home")
	}
	return home, nil
}

func validateWritableSource(project *os.File, profile config.Profile, uid uint32) (err error) {
	rootFD, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unix.Close(rootFD)) }()
	if err := trustedDirectory(rootFD); err != nil {
		return err
	}
	rootID, err := sourceAncestryOps.stat(rootFD)
	if err != nil {
		return err
	}
	var roots []int
	defer func() {
		for _, fd := range roots {
			err = errors.Join(err, unix.Close(fd))
		}
	}()
	for _, name := range sourceRuntimeRoots {
		fd, openErr := openRuntimeRoot(rootFD, name)
		if errors.Is(openErr, unix.ENOENT) && name != "usr" {
			// Only a missing top-level entry is optional; an existing dangling
			// alias is detected separately by openRuntimeRoot below.
			var st unix.Stat_t
			if statErr := unix.Fstatat(rootFD, name, &st, unix.AT_SYMLINK_NOFOLLOW); errors.Is(statErr, unix.ENOENT) {
				continue
			}
		}
		if openErr != nil {
			return fmt.Errorf("open runtime root %s: %w", name, openErr)
		}
		roots = append(roots, fd)
	}
	home, err := accountHome(rootFD, uid)
	if err != nil {
		return err
	}
	homeFD, err := unix.Open(home, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open account home: %w", err)
	}
	defer func() { err = errors.Join(err, unix.Close(homeFD)) }()
	// A bind alias can hide backing-directory ancestors from a namespace
	// parent walk. Reject alternate mounts of the source filesystem for the
	// trusted runtime/home roots rather than guessing their backing topology.
	if err := validateSourceMounts(int(project.Fd()), append(roots, homeFD)); err != nil {
		return err
	}
	return validateWritableSourceFDs(int(project.Fd()), profile, rootID, roots, homeFD, sourceAncestryOps)
}

// The FD roots are injected for unprivileged tests; production obtains them
// only from verified fixed system locations and the UID's local account.
func validateWritableSourceFDs(project int, profile config.Profile, root directoryID, roots []int, home int, ops ancestryOps) error {
	projectIDs, err := directoryAncestry(project, root, ops)
	if err != nil {
		return fmt.Errorf("project ancestry: %w", err)
	}
	for _, fd := range roots {
		ids, walkErr := directoryAncestry(fd, root, ops)
		if walkErr != nil {
			return fmt.Errorf("runtime ancestry: %w", walkErr)
		}
		if idIn(ids[0], projectIDs) || idIn(projectIDs[0], ids) {
			return errors.New("writable source overlaps trusted runtime execution")
		}
	}
	homeIDs, err := directoryAncestry(home, root, ops)
	if err != nil {
		return fmt.Errorf("account home ancestry: %w", err)
	}
	// If the home is outside the project, BENEATH rules cannot cover it.
	if !idIn(projectIDs[0], homeIDs) {
		return nil
	}
	for _, rule := range profile.Files {
		mutates := false
		for _, access := range rule.Access {
			mutates = mutates || access == "write" || access == "delete"
		}
		if !mutates {
			continue
		}
		fd, openErr := unix.Openat2(project, rule.Path, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS})
		if errors.Is(openErr, unix.ENOENT) {
			continue // a missing target cannot be the existing home or an ancestor
		}
		if openErr != nil {
			return fmt.Errorf("open mutation rule: %w", openErr)
		}
		var st unix.Stat_t
		statErr := unix.Fstat(fd, &st)
		closeErr := unix.Close(fd)
		if statErr != nil || closeErr != nil {
			return errors.Join(statErr, closeErr)
		}
		id := directoryID{st.Dev, st.Ino}
		if id == homeIDs[0] || rule.Recursive && idIn(id, homeIDs) {
			return errors.New("refusing writable whole-home rule")
		}
	}
	return nil
}
