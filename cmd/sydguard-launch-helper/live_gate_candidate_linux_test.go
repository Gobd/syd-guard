//go:build linux

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/syd"
	"golang.org/x/sys/unix"
)

// This ordinary opt-in checks the actual gate hold/release body under the
// candidate. It does not pretend the ordinary fixture has ROOT's empty group
// and bounding-capability setup or prove any privileged startup layout.
func TestLiveGateCandidateCompatibility(t *testing.T) {
	if os.Getenv("SYD_TEST_GATE_CHILD") == "1" {
		accepted, err := strconv.ParseUint(os.Getenv("SYD_TEST_GATE_START"), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		nonce, _ := decodeGateID(strings.Repeat("a", 64))
		ticket, _ := decodeGateID(strings.Repeat("b", 64))
		pid := os.Getpid()
		go func() {
			for {
				dump, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
				if err != nil {
					return
				}
				if dump == 0 {
					fmt.Printf("HELD %d\n", pid)
					return
				}
				time.Sleep(time.Millisecond)
			}
		}()
		if err := holdLiveGate(liveGateReleaseFD, nonce, ticket, accepted); err != nil {
			t.Fatal(err)
		}
		dump, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
		if err != nil || dump != 1 {
			t.Fatalf("dumpability not restored: %d %v", dump, err)
		}
		if err := syscall.Exec("/usr/bin/printf", []string{"printf", "AGENT %d\n", strconv.Itoa(pid)}, []string{"PATH=/usr/bin:/bin"}); err != nil {
			t.Fatal(err)
		}
		return
	}
	if os.Getenv("SYDGUARD_TEST_LIVE_GATE_CANDIDATE") != "1" {
		t.Skip("requires explicit ordinary candidate opt-in")
	}
	if os.Getuid() == 0 || os.Geteuid() != os.Getuid() {
		t.Fatal("ordinary user required")
	}
	candidate, err := os.ReadFile(liveTransportCandidate)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(candidate)
	if hex.EncodeToString(digest[:]) != liveEngineDigest {
		t.Fatal("candidate digest mismatch")
	}
	candidateInfo, err := os.Lstat(liveTransportCandidate)
	if err != nil {
		t.Fatal(err)
	}
	candidateStat := candidateInfo.Sys().(*syscall.Stat_t)
	if candidateStat.Uid != uint32(os.Getuid()) || candidateInfo.Mode().Perm() != 0o700 || !candidateInfo.Mode().IsRegular() {
		t.Fatal("untrusted candidate")
	}
	gate, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := elf.Open(gate)
	if err != nil {
		t.Fatal(err)
	}
	if binary.Type != elf.ET_DYN {
		t.Fatal("fixture gate is not PIE")
	}
	for _, p := range binary.Progs {
		if p.Type == elf.PT_INTERP {
			t.Fatal("fixture gate is dynamically linked")
		}
	}
	libs, err := binary.ImportedLibraries()
	if err != nil || len(libs) != 0 {
		t.Fatal("fixture gate has dynamic dependencies", err)
	}
	_ = binary.Close()
	gateInfo, err := os.Stat(gate)
	if err != nil {
		t.Fatal(err)
	}
	gateStat := gateInfo.Sys().(*syscall.Stat_t)
	root, err := os.MkdirTemp("/home/briankemper.guest", "syd-gate-proof-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	project, tmp, control := filepath.Join(root, "p"), filepath.Join(root, "t"), filepath.Join(root, "c")
	for _, p := range []string{project, tmp, control} {
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	binding := syd.BankBinding{Session: strings.Repeat("a", 64), Project: strings.Repeat("c", 64), Profile: "build", Generation: 1}
	spec := syd.RootWriterStartup{GatePath: gate, GateDev: uint64(gateStat.Dev), GateIno: uint64(gateStat.Ino), UID: uint32(os.Getuid()), GID: uint32(os.Getgid()), ReleaseFD: 3, WholeProjectRWD: true, RequirePIE: true}
	_, profile, err := syd.NewRootWriterBankLedger(binding, liveEngineDigest, project, tmp, filepath.Join(control, "s"), []string{control}, spec)
	if err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(control, "profile.syd-3")
	if err := os.WriteFile(profilePath, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	accepted, err := monotonicNanoseconds()
	if err != nil {
		t.Fatal(err)
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, liveTransportCandidate, "-P", profilePath, "--", gate, "-test.run=^TestLiveGateCandidateCompatibility$") //nolint:gosec // explicit ordinary fixture and exact candidate
	cmd.Dir = project
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/home/briankemper.guest", "TMPDIR=" + tmp, "SYD_TEST_GATE_CHILD=1", "SYD_TEST_GATE_START=" + strconv.FormatUint(accepted, 10)}
	cmd.ExtraFiles = []*os.File{read}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := os.Create(filepath.Join(control, "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = read.Close()
	waited := false
	defer func() {
		_ = write.Close()
		if !waited {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		if t.Failed() {
			data, _ := os.ReadFile(filepath.Join(control, "stderr"))
			t.Logf("candidate stderr: %s", data)
		}
	}()
	lines := make(chan string, 2)
	readErr := make(chan error, 1)
	go func() {
		r := bufio.NewReader(stdout)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				readErr <- err
				return
			}
			lines <- line
		}
	}()
	var pid string
	select {
	case line := <-lines:
		parts := strings.Fields(line)
		if len(parts) != 2 || parts[0] != "HELD" {
			t.Fatalf("gate not held: %q", line)
		}
		pid = parts[1]
	case err := <-readErr:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal("gate not ready")
	}
	select {
	case line := <-lines:
		t.Fatalf("selected execution before release: %q", line)
	case <-time.After(100 * time.Millisecond):
	}
	nonce, _ := decodeGateID(strings.Repeat("a", 64))
	ticket, _ := decodeGateID(strings.Repeat("b", 64))
	release := liveGateFrame(nonce, ticket)
	if _, err := write.Write(release[:]); err != nil {
		t.Fatal(err)
	}
	if err := write.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case line := <-lines:
		parts := strings.Fields(line)
		if len(parts) != 2 || parts[0] != "AGENT" || parts[1] != pid {
			t.Fatalf("bad released execution %q gate pid %s", line, pid)
		}
	case err := <-readErr:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal("gate did not release")
	}
	err = cmd.Wait()
	waited = true
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("candidate_sha256=%x engine_pid=%d gate_agent_pid=%s PIE=true held_nondumpable=true dumpable_exec=true passfd=3 no_pre_release_exec=true", digest, cmd.Process.Pid, pid)
}
