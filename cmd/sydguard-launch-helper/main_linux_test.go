//go:build linux

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/config"
	"golang.org/x/sys/unix"
)

func TestSupervisorWaitSIGKILLDiagnostic(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	err := cmd.Wait()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != -1 {
		t.Fatalf("expected signaled exit with code -1: %v", err)
	}
	status := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("unexpected status: %v", status)
	}
	code, resultErr := supervisorResult("wait", err, nil)
	if code != 1 || !errors.Is(resultErr, err) || !strings.Contains(resultErr.Error(), "supervisor wait") {
		t.Fatalf("signaled wait lost context or error: %d %v", code, resultErr)
	}
	message := supervisorWaitDiagnostic(cmd.Process.Pid, "wait", cmd.ProcessState, time.Second)
	for _, want := range []string{"branch=wait", "signaled=true", "signal=9", "exit_status=-1"} {
		if !strings.Contains(message, want) {
			t.Fatalf("missing %q in %q", want, message)
		}
	}
}

func TestWaitForSupervisorBranchesAndErrorPreservation(t *testing.T) {
	waitFailure := errors.New("supervisor failure")
	watchFailure := errors.New("watchdog failure")
	cleanupFailure := errors.New("cleanup failure")
	recoveryFailure := errors.New("recovery failure")
	for _, branch := range []string{"wait", "watchdog"} {
		t.Run(branch, func(t *testing.T) {
			wait := make(chan error, 1)
			watch := make(chan error, 1)
			stopped := false
			if branch == "wait" {
				wait <- waitFailure
			} else {
				watch <- watchFailure
			}
			gotBranch, gotWait, gotWatch := waitForSupervisor(wait, watch, func() {
				stopped = true
				wait <- waitFailure
			})
			if gotBranch != branch || gotWait != waitFailure || stopped != (branch == "watchdog") {
				t.Fatalf("branch=%s wait=%v stop=%t", gotBranch, gotWait, stopped)
			}
			launchErr := gotWait
			if gotWatch != nil {
				launchErr = errors.Join(gotWatch, gotWait)
			}
			code, err := combineLaunchErrors(0, launchErr, cleanupFailure, recoveryFailure)
			if code != 1 || !errors.Is(err, waitFailure) || !errors.Is(err, cleanupFailure) || !errors.Is(err, recoveryFailure) || (branch == "watchdog" && !errors.Is(err, watchFailure)) {
				t.Fatalf("lost error: code=%d err=%v", code, err)
			}
		})
	}
	code, err := combineLaunchErrors(17, waitFailure, nil, nil)
	if code != 17 || !errors.Is(err, waitFailure) {
		t.Fatalf("successful cleanup changed result: %d %v", code, err)
	}
	code, err = supervisorResult("watchdog", nil, watchFailure)
	if code != 1 || !errors.Is(err, watchFailure) {
		t.Fatalf("watchdog failure masked by successful supervisor wait: %d %v", code, err)
	}
}

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
