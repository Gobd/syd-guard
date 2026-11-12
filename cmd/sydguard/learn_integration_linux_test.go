//go:build linux

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/config"
	"golang.org/x/sys/unix"
)

func TestLearnCLINoNetworkCandidateIntegration(t *testing.T) {
	engine := os.Getenv("SYDGUARD_TEST_SYD")
	if engine == "" || os.Geteuid() == 0 {
		t.Skip("requires explicit unprivileged static Syd")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp(home, ".sydguard-learn-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(base) }()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "config"))
	work := filepath.Join(base, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(base, "input")
	if err := os.WriteFile(input, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	args := []string{"learn", "--backend", "native", "--no-network", "--accept-experimental-risks", "--syd", engine, "--directory", work, "--", "/bin/sh", "-c", `cat "$1" >/dev/null; printf x > "$2"; exit 7`, "fixture", input, filepath.Join(base, "output")}
	if code := run(args, &out, &stderr); code != 7 {
		t.Fatalf("exit=%d stderr=%s", code, &stderr)
	}
	if !strings.Contains(stderr.String(), "irreversible") || !strings.Contains(stderr.String(), "Private candidate") {
		t.Fatalf("missing disclosure: %s", &stderr)
	}
	store, err := candidateStore()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	records, err := store.Candidates()
	if err != nil || len(records) != 1 {
		t.Fatalf("records=%+v err=%v", records, err)
	}
	r := records[0]
	if r.ExitCode != 7 || !r.Candidate.Incomplete || !strings.Contains(strings.Join(r.Candidate.Reasons, ","), "abnormal-exit") || !strings.Contains(strings.Join(r.Candidate.Reasons, ","), "network-not-observed") {
		t.Fatalf("lost outcome: %+v", r)
	}
	found := false
	for _, file := range r.Candidate.Profile.Files {
		if file.Path == input {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing recorded read: %+v", r)
	}
	out.Reset()
	stderr.Reset()
	if code := run([]string{"learn", "show", r.ID}, &out, &stderr); code != 0 || !strings.Contains(out.String(), "file_checks") {
		t.Fatalf("show exit=%d out=%s err=%s", code, &out, &stderr)
	}
}

func TestLearnCLICancellationPreservesIncompleteCandidateIntegration(t *testing.T) {
	engine := os.Getenv("SYDGUARD_TEST_SYD")
	if engine == "" || os.Geteuid() == 0 {
		t.Skip("requires explicit unprivileged static Syd")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp(home, ".sydguard-learn-cancel-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(base) }()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "config"))
	work := filepath.Join(base, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	// A concurrent selected run may retain review.lock throughout its lifetime.
	// Cancellation must still persist the learning candidate independently.
	initialStore, err := candidateStore()
	if err != nil {
		t.Fatal(err)
	}
	_ = initialStore.Close()
	state, err := config.StateDirectory()
	if err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(state, config.PrivateAuthorityFolder, "candidates", "review.lock")
	fd, err := unix.Open(lockPath, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Flock(fd, unix.LOCK_UN) }()
	marker := filepath.Join(base, "after-cancel")
	var out, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	cmd := newCommand(&out, &stderr)
	err = cmd.Run(ctx, []string{"sydguard", "learn", "--backend", "native", "--no-network", "--accept-experimental-risks", "--syd", engine, "--directory", work, "--", "/bin/sh", "-c", `sleep 1; printf escaped > "$1"`, "fixture", marker})
	if err == nil || ctx.Err() == nil {
		t.Fatalf("cancellation not reported: %v %s", err, &stderr)
	}
	store, err := candidateStore()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	records, err := store.Candidates()
	if err != nil || len(records) != 1 || !records[0].Cancelled || !records[0].Candidate.Incomplete {
		t.Fatalf("cancellation lost: %+v %v", records, err)
	}
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("workload continued after cancellation: %v", err)
	}
}
