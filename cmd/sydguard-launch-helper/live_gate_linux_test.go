//go:build linux

package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/managedlive"
	"golang.org/x/sys/unix"
)

func TestLiveGateInputBindsOrdinaryIdentity(t *testing.T) {
	args := []string{"--live-gate", strings.Repeat("a", 64), strings.Repeat("b", 64), "12345", "502", "1000", "--", "/bin/true"}
	in, err := parseLiveGateInput(args, []string{"PATH=/usr/bin:/bin"})
	if err != nil || in.uid != 502 || in.gid != 1000 {
		t.Fatal(in, err)
	}
	for _, index := range []int{4, 5} {
		bad := append([]string(nil), args...)
		bad[index] = "0"
		if _, err := parseLiveGateInput(bad, []string{"PATH=/usr/bin:/bin"}); err == nil {
			t.Fatal("zero credential accepted")
		}
	}
	if _, err := parseLiveGateInput(args, []string{"PATH=/tmp"}); err == nil {
		t.Fatal("untrusted path accepted")
	}
}

func TestLiveGatePipeFrameAndDeadline(t *testing.T) {
	if os.Getenv("SYD_TEST_GATE_UNIT") != "" {
		accepted, err := strconv.ParseUint(os.Getenv("SYD_TEST_GATE_START"), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		nonce, _ := decodeGateID(strings.Repeat("a", 64))
		ticket, _ := decodeGateID(strings.Repeat("b", 64))
		err = holdLiveGate(3, nonce, ticket, accepted)
		if os.Getenv("SYD_TEST_GATE_UNIT") == "valid" {
			if err != nil {
				t.Fatal(err)
			}
			dump, e := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
			if e != nil || dump != 1 {
				t.Fatal("dumpability not restored", dump, e)
			}
			if _, e := unix.FcntlInt(3, unix.F_GETFD, 0); e == nil {
				t.Fatal("release FD survived")
			}
		} else if err == nil {
			t.Fatal("invalid release accepted")
		}
		return
	}
	if os.Getuid() == 0 {
		t.Skip("ordinary gate fixture")
	}
	for _, kind := range []string{"valid", "wrong", "trailing", "eof", "deadline"} {
		t.Run(kind, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			start, err := monotonicNanoseconds()
			if err != nil {
				t.Fatal(err)
			}
			if kind == "deadline" {
				start -= uint64(managedlive.StartupTimeout) + uint64(time.Second)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestLiveGatePipeFrameAndDeadline$") //nolint:gosec // test-owned self executable
			cmd.ExtraFiles = []*os.File{r}
			cmd.Env = append(os.Environ(), "SYD_TEST_GATE_UNIT="+kind, "SYD_TEST_GATE_START="+strconv.FormatUint(start, 10))
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			_ = r.Close()
			nonce, _ := decodeGateID(strings.Repeat("a", 64))
			ticket, _ := decodeGateID(strings.Repeat("b", 64))
			frame := liveGateFrame(nonce, ticket)
			if kind == "wrong" {
				frame[9] ^= 1
			}
			if kind != "eof" && kind != "deadline" {
				if _, err := w.Write(frame[:]); err != nil {
					t.Fatal(err)
				}
				if kind == "trailing" {
					if _, err := w.Write([]byte{1}); err != nil {
						t.Fatal(err)
					}
				}
			}
			_ = w.Close()
			if err := cmd.Wait(); err != nil {
				t.Fatalf("gate test child: %v", err)
			}
		})
	}
}

func TestLiveGateDeadlineAfterFrameAndRestore(t *testing.T) {
	if mode := os.Getenv("SYD_TEST_GATE_LATE"); mode != "" {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		nonce, _ := decodeGateID(strings.Repeat("a", 64))
		ticket, _ := decodeGateID(strings.Repeat("b", 64))
		frame := liveGateFrame(nonce, ticket)
		if _, err := w.Write(frame[:]); err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		fd, err := unix.Dup(int(r.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Close()
		const accepted = uint64(100)
		deadline := accepted + uint64(managedlive.StartupTimeout)
		now := accepted
		calls, polls := 0, 0
		clock := func() (uint64, error) {
			calls++
			if mode == "restore" && calls == 9 {
				now = deadline
			}
			return now, nil
		}
		poll := func(fds []unix.PollFd, timeout int) (int, error) {
			polls++
			if polls == 2 {
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
			}
			n, err := unix.Poll(fds, timeout)
			if mode == "eof" && polls == 2 {
				now = deadline
			}
			return n, err
		}
		if err := holdLiveGateWithClockPoll(fd, nonce, ticket, accepted, clock, poll); err == nil {
			t.Fatal("late release would execute selected program")
		}
		if polls != 2 {
			t.Fatalf("frame was not read before EOF: polls=%d", polls)
		}
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
			t.Fatal("owned release fd remained open")
		}
		dump, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
		if err != nil || dump != 0 {
			t.Fatalf("late gate is dumpable: %d %v", dump, err)
		}
		return
	}
	if os.Getuid() == 0 {
		t.Skip("ordinary gate fixture")
	}
	for _, mode := range []string{"eof", "restore"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestLiveGateDeadlineAfterFrameAndRestore$")
			cmd.Env = append(os.Environ(), "SYD_TEST_GATE_LATE="+mode)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("late child: %v: %s", err, output)
			}
		})
	}
}
