//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
)

const launchSlotsPerUID = 32

// The base directory is fixed and root-controlled. Slot files are persistent:
// unlinking one while another process holds its flock would break the limit.
type launchSlot struct {
	File        *os.File
	UID         uint32
	Index       int
	lifecycleMu sync.Mutex
}

func (s *launchSlot) Close() error { return s.File.Close() }

func slotName(uid uint32, index int) string {
	return "uid-" + strconv.FormatUint(uint64(uid), 10) + "-slot-" + strconv.Itoa(index)
}

func acquireLaunchSlot(baseFD int, uid uint32, owner uint32, recoverSlot func(*launchSlot) error) (*launchSlot, error) {
	for index := 0; index < launchSlotsPerUID; index++ {
		name := slotName(uid, index)
		flags := unix.O_RDWR | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		fd, err := unix.Openat(baseFD, name, flags|unix.O_CREAT|unix.O_EXCL, 0o600)
		created := err == nil
		if errors.Is(err, unix.EEXIST) {
			fd, err = unix.Openat(baseFD, name, flags, 0)
		}
		if err != nil {
			return nil, fmt.Errorf("open launch slot: %w", err)
		}
		file := os.NewFile(uintptr(fd), "launch-slot")
		if created {
			if err := unix.Fchmod(fd, 0o600); err != nil {
				_ = file.Close()
				return nil, err
			}
		}
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			_ = file.Close()
			return nil, err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o7777 != 0o600 || st.Uid != owner || st.Nlink != 1 || st.Size != 0 {
			_ = file.Close()
			return nil, errors.New("unsafe launch slot")
		}
		if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			_ = file.Close()
			if errors.Is(err, unix.EWOULDBLOCK) {
				continue
			}
			return nil, err
		}
		slot := &launchSlot{File: file, UID: uid, Index: index}
		if recoverSlot != nil {
			if err := recoverSlot(slot); err != nil {
				_ = file.Close()
				continue
			}
		}
		return slot, nil
	}
	return nil, errors.New("all managed launch slots are busy or quarantined")
}
