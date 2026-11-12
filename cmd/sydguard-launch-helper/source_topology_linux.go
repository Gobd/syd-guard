//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const maxSourceMountInfo = 4 * 1024 * 1024

func validateSourceNamespaceTopology(source sourceMount) (err error) {
	// Mount namespaces are per-thread. run keeps this thread locked; the
	// process leader's mountinfo may describe a different namespace.
	fd, err := unix.Open("/proc/thread-self/mountinfo", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "source-mount-topology")
	defer func() { err = errors.Join(err, file.Close()) }()
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return err
	}
	if fs.Type != unix.PROC_SUPER_MAGIC {
		return errors.New("source mount topology is not kernel procfs")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxSourceMountInfo+1))
	if err != nil {
		return err
	}
	return validateSourceMountInfo(source, data)
}

func mountNumber(value string, bits int) (uint64, error) {
	n, err := strconv.ParseUint(value, 10, bits)
	if err != nil || strconv.FormatUint(n, 10) != value {
		return 0, errors.New("invalid source mount topology number")
	}
	return n, nil
}

func validateSourceMountInfo(source sourceMount, data []byte) error {
	if source.mount == 0 || len(data) == 0 || len(data) > maxSourceMountInfo || data[len(data)-1] != '\n' || strings.ContainsRune(string(data), 0) {
		return errors.New("invalid or excessive source mount topology")
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) > 4096 {
		return errors.New("source mount topology exceeds mount limit")
	}
	seen := make(map[uint64]bool, len(lines))
	found := false
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 10 || !strings.HasPrefix(fields[3], "/") || !strings.HasPrefix(fields[4], "/") {
			return errors.New("invalid source mount topology record")
		}
		separator := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				separator = i
				break
			}
		}
		if separator < 6 || len(fields) != separator+4 {
			return errors.New("invalid source mount topology separator")
		}
		id, err := mountNumber(fields[0], 64)
		if err != nil || id == 0 || seen[id] {
			return errors.New("invalid or repeated source mount identity")
		}
		seen[id] = true
		if _, err := mountNumber(fields[1], 64); err != nil {
			return err
		}
		device := strings.Split(fields[2], ":")
		if len(device) != 2 {
			return errors.New("invalid source mount device")
		}
		major, err := mountNumber(device[0], 32)
		if err != nil {
			return err
		}
		minor, err := mountNumber(device[1], 32)
		if err != nil {
			return err
		}
		matches := major == uint64(unix.Major(source.device)) && minor == uint64(unix.Minor(source.device))
		if id == source.mount {
			if !matches {
				return errors.New("source mount device disagrees with its descriptor")
			}
			found = true
		} else if matches {
			// This includes aliases beneath runtime roots, not merely mounts
			// replacing those roots. Supporting their backing topology is a
			// separate gate; no pathname from mountinfo is opened as authority.
			return fmt.Errorf("unsupported alternate mount of writable source filesystem: %d", id)
		}
	}
	if !found {
		return errors.New("pinned source mount absent from thread namespace topology")
	}
	return nil
}
