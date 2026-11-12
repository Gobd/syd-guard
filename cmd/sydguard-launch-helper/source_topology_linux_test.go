//go:build linux

package main

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestWritableSourceRejectsDescendantRuntimeBindTopology(t *testing.T) {
	source := sourceMount{device: unix.Mkdev(252, 1), mount: 10}
	root := "10 1 252:1 / / rw,relatime - ext4 /dev/vda1 rw\n"
	proc := "20 10 0:15 / /proc rw - proc proc rw\n"
	for _, tc := range []struct {
		name, data string
		fail       bool
	}{
		{"ordinary disjoint namespace", root + proc, false},
		{"bind below runtime root", root + proc + "11 10 252:1 /tmp/P/runtime /usr/share/runtime-alias rw - ext4 /dev/vda1 rw\n", true},
		{"account home bind alias", root + "11 10 252:1 /tmp/P/home /home/account rw - ext4 /dev/vda1 rw\n", true},
		{"alternate source alias anywhere", root + "11 10 252:1 /tmp/P /other/alias rw - ext4 /dev/vda1 rw\n", true},
		{"distinct runtime filesystem", root + "11 10 252:2 / /usr rw - ext4 /dev/vdb1 rw\n", false},
		{"missing source mount", proc, true},
		{"source device mismatch", "10 1 252:2 / / rw - ext4 /dev/vdb1 rw\n", true},
		{"duplicate mount IDs", root + root, true},
		{"truncated mountinfo", strings.TrimSuffix(root, "\n"), true},
		{"malformed device", "10 1 nope / / rw - ext4 /dev/vda1 rw\n", true},
		{"malformed separator", "10 1 252:1 / / rw ext4 /dev/vda1 rw\n", true},
		{"empty record", root + "\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateSourceMountInfo(source, []byte(tc.data)); (err != nil) != tc.fail {
				t.Fatalf("unexpected topology outcome: %v", err)
			}
		})
	}
	if err := validateSourceMountInfo(source, make([]byte, maxSourceMountInfo+1)); err == nil {
		t.Fatal("accepted excessive kernel topology")
	}
	if err := validateSourceMountInfo(sourceMount{}, []byte(root)); err == nil {
		t.Fatal("accepted unknown source mount")
	}
}
