//go:build linux

package main

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCloseRangePreventsUnexpectedFDInheritance(t *testing.T) {
	switch os.Getenv("SYDGUARD_FD_FIXTURE") {
	case "verify":
		if _, err := unix.FcntlInt(100, unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
			t.Fatalf("unexpected descriptor survived exec: %v", err)
		}
		return
	case "mark":
		fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := unix.Dup3(fd, 100, 0); err != nil {
			t.Fatal(err)
		}
		_ = unix.Close(fd)
		if err := unix.CloseRange(3, ^uint(0), unix.CLOSE_RANGE_CLOEXEC); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestCloseRangePreventsUnexpectedFDInheritance$") //nolint:gosec // fixed test binary and fixed test name
		cmd.Env = append(os.Environ(), "SYDGUARD_FD_FIXTURE=verify")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("descriptor verification: %v %s", err, output)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestCloseRangePreventsUnexpectedFDInheritance$") //nolint:gosec // fixed test binary and fixed test name
	cmd.Env = append(os.Environ(), "SYDGUARD_FD_FIXTURE=mark")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("descriptor fixture: %v %s", err, output)
	}
}
