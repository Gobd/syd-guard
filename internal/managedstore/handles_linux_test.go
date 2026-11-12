//go:build linux

package managedstore

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDirectoryHandleValidation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		h     directoryHandle
		valid bool
	}{
		{"ext4 generation handle", directoryHandle{Type: 1, Data: "0001020304050607"}, true},
		{"wrong type", directoryHandle{Type: 2, Data: "0001020304050607"}, false},
		{"short", directoryHandle{Type: 1, Data: "00010203"}, false},
		{"upper case", directoryHandle{Type: 1, Data: "00010203040506FF"}, false},
		{"invalid hex", directoryHandle{Type: 1, Data: "00010203040506zz"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.h.fileHandle()
			if (err == nil) != tc.valid {
				t.Fatalf("handle validation: %v", err)
			}
		})
	}
	if _, err := openDirectoryHandle(-1, nil, 1, 1); err == nil {
		t.Fatal("unpinned registration accepted")
	}
}

func TestRegistrationHandleParsing(t *testing.T) {
	base := `{"project":"/project","project_dev":1,"project_ino":2,"policy_dev":1,"policy_ino":3`
	handle := `{"type":1,"data":"0001020304050607"}`
	for _, tc := range []struct {
		name, data string
		valid      bool
	}{
		{"legacy remains readable", base + `}`, true},
		{"paired", base + `,"project_handle":` + handle + `,"policy_handle":` + handle + `}`, true},
		{"single handle", base + `,"project_handle":` + handle + `}`, false},
		{"null handle", base + `,"project_handle":null,"policy_handle":` + handle + `}`, false},
		{"duplicate handle field", base + `,"project_handle":{"type":1,"type":1,"data":"0001020304050607"},"policy_handle":` + handle + `}`, false},
		{"unknown handle field", base + `,"project_handle":{"type":1,"data":"0001020304050607","extra":1},"policy_handle":` + handle + `}`, false},
		{"bad handle", base + `,"project_handle":` + strings.Replace(handle, "0001020304050607", "00", 1) + `,"policy_handle":` + handle + `}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseRegistration([]byte(tc.data))
			if (err == nil) != tc.valid {
				t.Fatalf("registration parsing: %v", err)
			}
		})
	}
}

func TestOpenPinnedSnapshotRejectsInvalidSelectionBeforeAccess(t *testing.T) {
	var store Store
	id := strings.Repeat("a", 64)
	for _, selection := range [][3]string{
		{"bad", "default", id},
		{id, "../bad", id},
		{id, "default", "bad"},
	} {
		if _, err := store.OpenPinnedSnapshot("", selection[0], selection[1], selection[2]); err == nil {
			t.Fatalf("accepted invalid selection: %q", selection)
		}
	}
}

func TestCaptureDirectoryHandleRejectsNonExt4(t *testing.T) {
	fd, err := unix.Open("/proc", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("proc unavailable: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()
	if _, err := captureDirectoryHandle(fd, fd); err == nil {
		t.Fatal("non-ext4 filesystem accepted")
	}
}
