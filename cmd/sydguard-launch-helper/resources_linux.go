//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func openCgroupBase() (int, error) {
	if _, err := trustedPath(cgroupBase, false); err != nil {
		return -1, err
	}
	fd, err := unix.Open(cgroupBase, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if fs.Type != unix.CGROUP2_SUPER_MAGIC {
		_ = unix.Close(fd)
		return -1, errors.New("managed launch requires a dedicated cgroup v2 root")
	}
	return fd, nil
}

// prepareSlot journals intent durably before creating either bounded resource.
// A crash before the ready journal quarantines this slot; it is never guessed
// safe or reused automatically.
func prepareSlot(baseFD, cgroupFD int, slot *launchSlot, parentIdentity string, owner uint32, probe func(int, time.Duration) error) (slotJournal, *os.File, error) {
	j, err := newJournal(slot, parentIdentity)
	if err != nil {
		return j, nil, err
	}
	if err := writeJournal(baseFD, slot, j, true); err != nil {
		return j, nil, err
	}
	if err := unix.Mkdirat(baseFD, anchorName(slot), 0o755); err != nil {
		return j, nil, err
	}
	anchorFD, err := unix.Openat(baseFD, anchorName(slot), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return j, nil, err
	}
	defer func() { _ = unix.Close(anchorFD) }()
	if err := unix.Fchmod(anchorFD, 0o755); err != nil {
		return j, nil, err
	}
	var a, g unix.Stat_t
	if err := unix.Fstat(anchorFD, &a); err != nil {
		return j, nil, err
	}
	if a.Uid != owner || a.Mode&0o7777 != 0o755 {
		return j, nil, errors.New("invalid new anchor")
	}
	name := slotName(slot.UID, slot.Index)
	if err := unix.Mkdirat(cgroupFD, name, 0o755); err != nil {
		return j, nil, err
	}
	group, err := unix.Openat(cgroupFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return j, nil, err
	}
	file := os.NewFile(uintptr(group), "launch-cgroup")
	if err := unix.Fstat(group, &g); err != nil {
		_ = file.Close()
		return j, nil, err
	}
	if g.Uid != owner || g.Mode&0o022 != 0 {
		_ = file.Close()
		return j, nil, errors.New("unsafe new cgroup")
	}
	if err := probe(group, 5*time.Second); err != nil {
		_ = file.Close()
		return j, nil, err
	}
	j.Phase, j.AnchorDev, j.AnchorIno, j.CgroupDev, j.CgroupIno = "ready", a.Dev, a.Ino, g.Dev, g.Ino
	if err := writeJournal(baseFD, slot, j, false); err != nil {
		_ = file.Close()
		return j, nil, err
	}
	return j, file, nil
}

// probeCgroupCleanup checks the fresh, empty domain cgroup without issuing a
// kill. A successful open does not guarantee that a later kill write succeeds;
// cleanup still performs the write and quarantines the slot on failure.
func probeCgroupCleanup(fd int, _ time.Duration) error {
	var group unix.Stat_t
	if err := unix.Fstat(fd, &group); err != nil {
		return err
	}
	if group.Mode&unix.S_IFMT != unix.S_IFDIR || group.Mode&0o022 != 0 {
		return errors.New("unsafe cgroup directory")
	}
	openFile := func(name string, flags int) (*os.File, error) {
		child, err := unix.Openat(fd, name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			return nil, err
		}
		file := os.NewFile(uintptr(child), name)
		var st unix.Stat_t
		if err := unix.Fstat(child, &st); err != nil {
			_ = file.Close()
			return nil, err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != group.Uid || st.Dev != group.Dev || st.Mode&0o022 != 0 {
			_ = file.Close()
			return nil, errors.New("unsafe cgroup interface")
		}
		return file, nil
	}
	readFile := func(name string) ([]byte, error) {
		file, err := openFile(name, unix.O_RDONLY)
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(file, 4097))
		closeErr := file.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if len(data) > 4096 {
			return nil, errors.New("oversized cgroup interface")
		}
		return data, nil
	}
	kind, err := readFile("cgroup.type")
	if err != nil {
		return fmt.Errorf("read cgroup type: %w", err)
	}
	if string(kind) != "domain\n" {
		return errors.New("cgroup is not a domain")
	}
	events, err := readFile("cgroup.events")
	if err != nil {
		return fmt.Errorf("read cgroup events: %w", err)
	}
	if len(events) == 0 || events[len(events)-1] != '\n' {
		return errors.New("invalid cgroup events")
	}
	seen := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSuffix(string(events), "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || seen[fields[0]] || !cgroupEventName(fields[0]) || !cgroupEventValue(fields[1]) {
			return errors.New("invalid cgroup events")
		}
		seen[fields[0]] = true
		if fields[0] == "populated" && fields[1] != "0" {
			return errors.New("cgroup is not empty")
		}
		if fields[0] == "frozen" && fields[1] != "0" && fields[1] != "1" {
			return errors.New("invalid cgroup frozen state")
		}
	}
	if !seen["populated"] {
		return errors.New("missing cgroup populated state")
	}
	kill, err := openFile("cgroup.kill", unix.O_WRONLY)
	if err != nil {
		return fmt.Errorf("cgroup kill unavailable: %w", err)
	}
	return kill.Close()
}

func cgroupEventName(s string) bool {
	for i, c := range s {
		if (c < 'a' || c > 'z') && c != '_' && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return s != ""
}

func cgroupEventValue(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}
