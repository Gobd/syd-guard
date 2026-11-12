//go:build linux || darwin

package controller

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func owned(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return fmt.Errorf("controller authority is not operator-owned")
	}
	return nil
}

func lockController(directory string) (*os.File, error) {
	path := filepath.Join(directory, "controller.lock")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0) {
		err = fmt.Errorf("invalid private controller lock")
	}
	if err == nil {
		err = owned(info)
	}
	if err == nil {
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
	}
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("controller lock: %w", err)
	}
	return file, nil
}
