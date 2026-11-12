//go:build linux

package main

import (
	"errors"
	"os"
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
func prepareSlot(baseFD, cgroupFD int, slot *launchSlot, parentIdentity string, owner uint32, kill func(int, time.Duration) error) (slotJournal, *os.File, error) {
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
	if err := kill(group, 5*time.Second); err != nil {
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
