//go:build linux

// sydguard-policy-helper is a one-shot, root-installed policy storage helper.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Gobd/syd-guard/internal/managedstore"
	"golang.org/x/sys/unix"
)

const (
	registry   = "/var/lib/sydguard-policy"
	executable = "/usr/local/libexec/sydguard-policy-helper"
)

func main() {
	// Bound stalled stdin, lock waits, and operations even if the client disappears.
	timer := time.AfterFunc(20*time.Second, func() { os.Exit(124) })
	response := run()
	err := json.NewEncoder(os.Stdout).Encode(response)
	timer.Stop()
	if err != nil || response.Error != "" {
		os.Exit(1)
	}
}

func fail(code, message string) managedstore.Response {
	return managedstore.Response{Code: code, Error: message}
}

func run() managedstore.Response {
	if os.Geteuid() != 0 {
		return fail("forbidden", "root helper required")
	}
	if err := verifyInstallation(); err != nil {
		return fail("installation", "untrusted helper installation")
	}
	if len(os.Args) != 1 {
		return fail("invalid", "unsupported arguments")
	}
	uid, err := parseUID(os.Getenv("SUDO_UID"))
	if err != nil {
		return fail("forbidden", "validated sudo caller UID required")
	}
	request, err := managedstore.DecodeRequest(os.Stdin)
	if err != nil {
		return fail("invalid", "invalid request")
	}
	store, err := managedstore.Open(registry, uid)
	if err != nil {
		return fail("store", "registry unavailable")
	}
	defer func() { _ = store.Close() }()
	response, err := store.Apply(request)
	if errors.Is(err, managedstore.ErrIndeterminate) {
		return fail("indeterminate", "operation may have committed; reconcile before retry")
	}
	if errors.Is(err, managedstore.ErrUnsupportedFilesystem) {
		return fail("unsupported_filesystem", "project and registry require the same verified local ext4/tmpfs filesystem")
	}
	if errors.Is(err, managedstore.ErrConflict) {
		return fail("409", "profile revision conflict")
	}
	if err != nil {
		return fail("rejected", "operation rejected")
	}
	return response
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
