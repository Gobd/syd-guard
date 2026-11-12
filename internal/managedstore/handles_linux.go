//go:build linux

package managedstore

import (
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// ext4's FILEID_INO32_GEN handle contains both the inode and its generation.
// Other filesystems and handle forms have not been proved suitable for launch.
type directoryHandle struct {
	Type int32  `json:"type"`
	Data string `json:"data"`
}

func (h directoryHandle) fileHandle() (unix.FileHandle, error) {
	data, err := hex.DecodeString(h.Data)
	if err != nil || h.Type != 1 || len(data) != 8 || hex.EncodeToString(data) != h.Data {
		return unix.FileHandle{}, errors.New("invalid ext4 generation-bearing directory handle")
	}
	return unix.NewFileHandle(h.Type, data), nil
}

// captureDirectoryHandle uses the already-open directory rather than its name.
// It also proves the registry mount can reopen the handle while privileged.
func captureDirectoryHandle(mountFD, directoryFD int) (*directoryHandle, error) {
	var fs unix.Statfs_t
	if err := unix.Fstatfs(directoryFD, &fs); err != nil {
		return nil, err
	}
	if fs.Type != unix.EXT4_SUPER_MAGIC {
		return nil, errors.New("pinned registration requires ext4 generation-bearing handles")
	}
	handle, _, err := unix.NameToHandleAt(directoryFD, "", unix.AT_EMPTY_PATH)
	if err != nil {
		return nil, fmt.Errorf("capture directory handle: %w", err)
	}
	stored := &directoryHandle{Type: handle.Type(), Data: hex.EncodeToString(handle.Bytes())}
	if _, err := stored.fileHandle(); err != nil {
		return nil, err
	}
	var expected unix.Stat_t
	if err := unix.Fstat(directoryFD, &expected); err != nil {
		return nil, err
	}
	reopened, err := openDirectoryHandle(mountFD, stored, expected.Dev, expected.Ino)
	if err != nil {
		return nil, fmt.Errorf("verify directory handle: %w", err)
	}
	if err := unix.Close(reopened); err != nil {
		return nil, err
	}
	return stored, nil
}

func openDirectoryHandle(mountFD int, stored *directoryHandle, dev, ino uint64) (int, error) {
	if stored == nil || ino == 0 {
		return -1, errors.New("registration has no pinned directory handle")
	}
	handle, err := stored.fileHandle()
	if err != nil {
		return -1, err
	}
	fd, err := unix.OpenByHandleAt(mountFD, handle, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC)
	if err != nil {
		return -1, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if st.Dev != dev || st.Ino != ino || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		_ = unix.Close(fd)
		return -1, errors.New("reopened directory identity changed")
	}
	return fd, nil
}
