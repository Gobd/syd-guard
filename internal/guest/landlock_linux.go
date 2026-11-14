//go:build linux

package guest

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func checkLandlock() error {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return fmt.Errorf("requested Landlock is unavailable: %w (disable it explicitly or use a supporting kernel)", errno)
	}
	if abi < 3 {
		return fmt.Errorf("kernel Landlock ABI %d is too old; ABI 3+ is required for rename/truncate enforcement", abi)
	}
	return nil
}
