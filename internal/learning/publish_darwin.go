//go:build darwin

package learning

import "golang.org/x/sys/unix"

func publishNoReplace(dir int, temporary, final string) error {
	return unix.RenameatxNp(dir, temporary, dir, final, unix.RENAME_EXCL)
}
