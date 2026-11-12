//go:build linux || darwin

package config

import (
	"fmt"
	"os"
	"syscall"
)

func checkOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return fmt.Errorf("operator config must be owned by the current user")
	}
	return nil
}
