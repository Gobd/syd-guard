//go:build linux

// sydguard-policy-admin is a separately authorized enrollment executable.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Gobd/syd-guard/internal/managedstore"
	"golang.org/x/sys/unix"
)

const (
	registry   = "/var/lib/sydguard-policy"
	executable = "/usr/local/libexec/sydguard-policy-admin"
)

func main() {
	response := run()
	if err := json.NewEncoder(os.Stdout).Encode(response); err != nil {
		os.Exit(1)
	}
	if response.Error != "" {
		os.Exit(1)
	}
}

func fail(code, message string) managedstore.Response {
	return managedstore.Response{Code: code, Error: message}
}

func run() managedstore.Response {
	if os.Geteuid() != 0 || verifyInstallation() != nil {
		return fail("installation", "untrusted admin installation")
	}
	if len(os.Args) != 3 {
		return fail("invalid", "UID and credential path required")
	}
	uid, err := parseUID(os.Args[1])
	if err != nil {
		return fail("invalid", "invalid enrollment UID")
	}
	store, err := managedstore.Open(registry, uid)
	if err != nil {
		return fail("store", "registry unavailable")
	}
	defer func() { _ = store.Close() }()
	if err := store.Bootstrap(os.Args[2]); err != nil {
		if errors.Is(err, managedstore.ErrIndeterminate) {
			return fail("indeterminate", "enrollment may have committed; administrator inspection required")
		}
		return fail("enrollment", "credential enrollment rejected")
	}
	return managedstore.Response{}
}

func parseUID(value string) (int, error) {
	if value == "" || strings.Trim(value, "0123456789") != "" {
		return 0, fmt.Errorf("invalid uid")
	}
	uid, err := strconv.ParseUint(value, 10, 31)
	if err != nil || uid == 0 {
		return 0, fmt.Errorf("invalid uid")
	}
	return int(uid), nil
}

// Every component is traversed without symlinks; only root can alter it.
func trustedPath(path string, file bool) (unix.Stat_t, error) {
	var stat unix.Stat_t
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return stat, err
	}
	defer func() { _ = unix.Close(fd) }()
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if i < len(parts)-1 || !file {
			flags |= unix.O_DIRECTORY
		}
		next, e := unix.Openat(fd, part, flags, 0)
		if e != nil {
			return stat, e
		}
		_ = unix.Close(fd)
		fd = next
		if e = unix.Fstat(fd, &stat); e != nil {
			return stat, e
		}
		if stat.Uid != 0 || stat.Mode&0o022 != 0 {
			return stat, fmt.Errorf("untrusted owner or mode")
		}
	}
	if file && (stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Mode&0o111 == 0) {
		return stat, fmt.Errorf("invalid executable")
	}
	return stat, nil
}

func verifyInstallation() error {
	path, err := os.Readlink("/proc/self/exe")
	if err != nil || path != executable || filepath.Clean(path) != path {
		return fmt.Errorf("unexpected executable")
	}
	expected, err := trustedPath(executable, true)
	if err != nil {
		return err
	}
	var self unix.Stat_t
	if err := unix.Stat("/proc/self/exe", &self); err != nil {
		return err
	}
	if self.Dev != expected.Dev || self.Ino != expected.Ino {
		return fmt.Errorf("executable changed")
	}
	_, err = trustedPath(registry, false)
	return err
}
