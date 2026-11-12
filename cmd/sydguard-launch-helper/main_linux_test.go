//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Gobd/syd-guard/internal/config"
	"golang.org/x/sys/unix"
)

func TestValidateIntent(t *testing.T) {
	for _, tc := range []struct {
		name     string
		profile  config.Profile
		accepted bool
	}{
		{"read", config.Profile{Files: []config.FileRule{{Path: ".", Access: []string{"read"}, Recursive: true}}}, true},
		{"write", config.Profile{Files: []config.FileRule{{Path: "file", Access: []string{"write"}}}}, false},
		{"absolute", config.Profile{Files: []config.FileRule{{Path: "/etc", Access: []string{"read"}}}}, false},
		{"home", config.Profile{Files: []config.FileRule{{Path: "~/file", Access: []string{"read"}}}}, false},
		{"network", config.Profile{Network: []config.NetworkRule{{Host: "example.com", Port: 443, Transport: "tcp"}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateIntent(tc.profile); (err == nil) != tc.accepted {
				t.Fatalf("validation: %v", err)
			}
		})
	}
}

func TestCheckAnonymousPipeRejectsNamedFIFOAndFiles(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close(); _ = writer.Close() }()
	if err := checkAnonymousPipe(int(reader.Fd())); err != nil {
		t.Fatal(err)
	}
	if err := checkAnonymousPipe(int(writer.Fd())); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := checkAnonymousPipe(fd); err == nil {
		t.Fatal("accepted named FIFO")
	}
	file, err := os.CreateTemp(t.TempDir(), "file-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if err := checkAnonymousPipe(int(file.Fd())); err == nil {
		t.Fatal("accepted regular file")
	}
}

func TestSudoIDRejectsInvalidValues(t *testing.T) {
	for _, value := range []string{"", "0", "-1", "1x", "2147483648"} {
		t.Setenv("SUDO_UID", value)
		if _, err := sudoID("SUDO_UID"); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
	t.Setenv("SUDO_UID", "1000")
	if uid, err := sudoID("SUDO_UID"); err != nil || uid != 1000 {
		t.Fatalf("valid UID: %d %v", uid, err)
	}
}
