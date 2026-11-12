//go:build linux

package learning

import "golang.org/x/sys/unix"

func publishNoReplace(dir int, temporary, final string) error {
	return unix.Renameat2(dir, temporary, dir, final, unix.RENAME_NOREPLACE)
}
