//go:build linux

package main

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

type sourceMount struct {
	device uint64
	mount  uint64
}

func directoryMount(fd int) (sourceMount, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return sourceMount{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return sourceMount{}, errors.New("source mount descriptor is not a directory")
	}
	var info unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, unix.STATX_MNT_ID, &info); err != nil {
		return sourceMount{}, err
	}
	if info.Mask&unix.STATX_MNT_ID == 0 || info.Mnt_id == 0 {
		return sourceMount{}, errors.New("source mount identity unavailable")
	}
	return sourceMount{device: st.Dev, mount: info.Mnt_id}, nil
}

func validateSourceMounts(project int, roots []int) error {
	if err := validateSourceMountsWith(project, roots, directoryMount); err != nil {
		return err
	}
	source, err := directoryMount(project)
	if err != nil {
		return err
	}
	return validateSourceNamespaceTopology(source)
}

func validateSourceMountsWith(project int, roots []int, identify func(int) (sourceMount, error)) error {
	source, err := identify(project)
	if err != nil {
		return fmt.Errorf("identify pinned source mount: %w", err)
	}
	if source.mount == 0 {
		return errors.New("pinned source mount identity unavailable")
	}
	for _, fd := range roots {
		root, err := identify(fd)
		if err != nil {
			return fmt.Errorf("identify trusted directory mount: %w", err)
		}
		if root.mount == 0 {
			return errors.New("trusted directory mount identity unavailable")
		}
		if source.device == root.device && source.mount != root.mount {
			return errors.New("writable source filesystem has a trusted runtime or home mount alias")
		}
	}
	return nil
}
