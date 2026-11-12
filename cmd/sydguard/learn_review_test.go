//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/learning"
	"github.com/Gobd/syd-guard/internal/managedstore"
)

func TestLearnReviewIndeterminateABACannotEstablishCommit(t *testing.T) {
	fixture, root := managedCommandTestSetup(t)
	store, err := candidateStore()
	if err != nil {
		t.Fatal(err)
	}
	candidate := learning.ProfileCandidate{Profile: config.Profile{Version: 1, Name: "default", Files: []config.FileRule{}, Network: []config.NetworkRule{}}, Kind: "permission-check-candidate", Incomplete: true, Reasons: []string{"network-not-observed"}}
	id, err := store.SaveCandidate(learning.CandidateRecord{Project: root, Candidate: candidate})
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	data, err := json.Marshal(candidate.Profile)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := config.ParseProfileSnapshot("default", data)
	if err != nil {
		t.Fatal(err)
	}
	project, expected := strings.Repeat("a", 64), strings.Repeat("b", 64)
	args := []string{"learn", "save", "--experimental", "--yes", "--candidate", id, "--project-id", project, "--expected-revision", expected}
	if _, err := managedRun(args, string(data)); err == nil || len(fixture.calls) != 0 {
		t.Fatal("incomplete candidate saved without acknowledgement")
	}
	fixture.failure = managedstore.ErrIndeterminate
	args = append(args, "--accept-incomplete")
	output, err := managedRun(args, string(data))
	if !errors.Is(err, managedstore.ErrIndeterminate) {
		t.Fatalf("indeterminate lost: %s %v", output, err)
	}
	fields := strings.Fields(output)
	if len(fields) < 2 || fields[0] != "Review" {
		t.Fatalf("missing pending review ID: %q", output)
	}
	review := fields[1]
	fixture.calls = nil
	if _, err := managedRun(args, string(data)); err == nil || len(fixture.calls) != 0 {
		t.Fatal("unresolved CAS was retried")
	}
	fixture.failure = nil
	intervening := []byte(`{"version":1,"name":"default","files":[{"path":"/changed","access":["read"],"recursive":false}],"network":[]}`)
	other, err := config.ParseManagedProfileSnapshot("default", intervening)
	if err != nil {
		t.Fatal(err)
	}
	fixture.response = managedstore.Response{Project: project, Name: "default", Revision: other.Revision(), Profile: intervening}
	output, err = managedRun([]string{"learn", "reconcile", "--experimental", "--review", review}, "")
	if err != nil || !strings.Contains(output, `"matches_reviewed_bytes":false`) || !strings.Contains(output, `"operation_status":"unknown"`) {
		t.Fatalf("intervening snapshot: %s %v", output, err)
	}
	// A later writer restores the desired bytes: an ABA match is not our CAS acknowledgement.
	fixture.response = managedstore.Response{Project: project, Name: "default", Revision: snapshot.Revision(), Profile: data}
	output, err = managedRun([]string{"learn", "reconcile", "--experimental", "--review", review}, "")
	if err != nil || !strings.Contains(output, `"operation_status":"unknown"`) || !strings.Contains(output, `"matches_reviewed_bytes":true`) {
		t.Fatalf("reconcile: %s %v", output, err)
	}
	store, err = candidateStore()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	if _, _, err := store.VerifyProvenance(project, "default", snapshot.Revision()); !errors.Is(err, learning.ErrReviewPending) {
		t.Fatalf("matching reread improperly established provenance: %v", err)
	}
	if _, err := managedRun([]string{"learn", "authorize-current", "--experimental", "--yes", "--review", review, "--expected-current-revision", snapshot.Revision()}, ""); err == nil {
		t.Fatal("missing unknown-operation acknowledgement")
	}
	output, err = managedRun([]string{"learn", "authorize-current", "--experimental", "--yes", "--accept-unknown-operation", "--review", review, "--expected-current-revision", snapshot.Revision()}, "")
	if err != nil || !strings.Contains(output, `"status":"current-authorized"`) || !strings.Contains(output, `"operation_status":"unknown"`) {
		t.Fatalf("independent current authorization: %s %v", output, err)
	}
	if _, _, err := store.VerifyProvenance(project, "default", snapshot.Revision()); !errors.Is(err, learning.ErrCurrentAuthorized) {
		t.Fatalf("current authorization was incorrectly labelled learning provenance: %v", err)
	}
	_, result, err := store.Review(review)
	if err != nil || result == nil || result.Status != "current-authorized" || result.OperationStatus != "unknown" {
		t.Fatalf("lost uncertain operation: %+v %v", result, err)
	}
	summaries, err := store.ReviewSummaries()
	if err != nil || len(summaries) != 1 || summaries[0].OperationStatus != "unknown" {
		t.Fatalf("summary omitted unknown operation: %+v %v", summaries, err)
	}
}

func TestLearnReviewNoopIndeterminateRemainsUnknown(t *testing.T) {
	fixture, root := managedCommandTestSetup(t)
	s, err := candidateStore()
	if err != nil {
		t.Fatal(err)
	}
	candidate := learning.ProfileCandidate{Profile: config.Profile{Version: 1, Name: "default", Files: []config.FileRule{}, Network: []config.NetworkRule{}}, Kind: "permission-check-candidate"}
	id, err := s.SaveCandidate(learning.CandidateRecord{Project: root, Candidate: candidate})
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	data, _ := json.Marshal(candidate.Profile)
	snapshot, err := config.ParseProfileSnapshot("default", data)
	if err != nil {
		t.Fatal(err)
	}
	project := strings.Repeat("a", 64)
	fixture.failure = managedstore.ErrIndeterminate
	output, err := managedRun([]string{"learn", "save", "--experimental", "--yes", "--candidate", id, "--project-id", project, "--expected-revision", snapshot.Revision()}, string(data))
	if !errors.Is(err, managedstore.ErrIndeterminate) {
		t.Fatalf("indeterminate no-op: %s %v", output, err)
	}
	review := strings.Fields(output)[1]
	fixture.failure = nil
	fixture.response = managedstore.Response{Project: project, Name: "default", Revision: snapshot.Revision(), Profile: data}
	output, err = managedRun([]string{"learn", "reconcile", "--experimental", "--review", review}, "")
	if err != nil || !strings.Contains(output, `"operation_status":"unknown"`) {
		t.Fatalf("no-op was attributed: %s %v", output, err)
	}
	s, err = candidateStore()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if _, _, err := s.VerifyProvenance(project, "default", snapshot.Revision()); !errors.Is(err, learning.ErrReviewPending) {
		t.Fatalf("no-op lost unknown: %v", err)
	}
}

func TestLearnReviewNotSubmittedAllowsCorrectedRetry(t *testing.T) {
	fixture, root := managedCommandTestSetup(t)
	s, err := candidateStore()
	if err != nil {
		t.Fatal(err)
	}
	candidate := learning.ProfileCandidate{Profile: config.Profile{Version: 1, Name: "default", Files: []config.FileRule{}, Network: []config.NetworkRule{}}, Kind: "permission-check-candidate"}
	id, err := s.SaveCandidate(learning.CandidateRecord{Project: root, Candidate: candidate})
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	data, _ := json.Marshal(candidate.Profile)
	snapshot, err := config.ParseProfileSnapshot("default", data)
	if err != nil {
		t.Fatal(err)
	}
	project, expected := strings.Repeat("a", 64), strings.Repeat("b", 64)
	args := []string{"learn", "save", "--experimental", "--yes", "--candidate", id, "--project-id", project, "--expected-revision", expected}
	fixture.failure = managedstore.ErrNotSubmitted
	output, err := managedRun(args, string(data))
	if !errors.Is(err, managedstore.ErrNotSubmitted) {
		t.Fatalf("preflight: %s %v", output, err)
	}
	fixture.failure = nil
	fixture.response = managedstore.Response{Project: project, Name: "default", Revision: snapshot.Revision(), Profile: data}
	output, err = managedRun(args, string(data))
	if err != nil {
		t.Fatalf("corrected retry blocked: %s %v", output, err)
	}
}

func TestLearnPendingIDOutputFailureDoesNotSubmit(t *testing.T) {
	fixture, root := managedCommandTestSetup(t)
	s, err := candidateStore()
	if err != nil {
		t.Fatal(err)
	}
	candidate := learning.ProfileCandidate{Profile: config.Profile{Version: 1, Name: "default", Files: []config.FileRule{}, Network: []config.NetworkRule{}}, Kind: "permission-check-candidate"}
	id, err := s.SaveCandidate(learning.CandidateRecord{Project: root, Candidate: candidate})
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	data, _ := json.Marshal(candidate.Profile)
	cmd := newCommand(io.Discard, failedManagedOutput{errors.New("stderr unavailable")})
	cmd.Reader = bytes.NewReader(data)
	err = cmd.Run(context.Background(), []string{"sydguard", "learn", "save", "--experimental", "--yes", "--candidate", id, "--project-id", strings.Repeat("a", 64), "--expected-revision", strings.Repeat("b", 64)})
	if !errors.Is(err, managedstore.ErrNotSubmitted) || len(fixture.calls) != 0 {
		t.Fatalf("output failure submitted: %v calls=%v", err, fixture.calls)
	}
	output, err := managedRun([]string{"learn", "review-list"}, "")
	if err != nil || !strings.Contains(output, `"status":"rejected"`) {
		t.Fatalf("review discovery: %s %v", output, err)
	}
}

func TestLearnSaveBrokenStdoutAfterCommitSubprocess(t *testing.T) {
	if os.Getenv("SYDGUARD_LEARN_PIPE_CHILD") == "1" {
		data := []byte(`{"version":1,"name":"default","files":[],"network":[]}`)
		snapshot, err := config.ParseManagedProfileSnapshot("default", data)
		if err != nil {
			os.Exit(3)
		}
		project := strings.Repeat("a", 64)
		fixture := &managedCommandFixture{response: managedstore.Response{Project: project, Name: "default", Revision: snapshot.Revision(), Profile: data}}
		managedCheckPlatform = func() error { return nil }
		managedOpen = func(string) (managedClient, error) { return fixture, nil }
		cmd := newCommand(os.Stdout, os.Stderr)
		cmd.Reader = bytes.NewReader(data)
		err = cmd.Run(context.Background(), []string{"sydguard", "learn", "save", "--experimental", "--yes", "--candidate", os.Getenv("SYDGUARD_LEARN_CANDIDATE"), "--project-id", project, "--expected-revision", strings.Repeat("b", 64)})
		if !errors.Is(err, managedstore.ErrIndeterminate) || !strings.Contains(err.Error(), "committed and bound") {
			os.Exit(4)
		}
		_, _ = io.WriteString(os.Stderr, "COMMITTED_REVIEW_RECOVERY\n")
		os.Exit(0)
	}
	_, root := managedCommandTestSetup(t)
	s, err := candidateStore()
	if err != nil {
		t.Fatal(err)
	}
	candidate := learning.ProfileCandidate{Profile: config.Profile{Version: 1, Name: "default", Files: []config.FileRule{}, Network: []config.NetworkRule{}}, Kind: "permission-check-candidate"}
	id, err := s.SaveCandidate(learning.CandidateRecord{Project: root, Candidate: candidate})
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := read.Close(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = write.Close() }()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestLearnSaveBrokenStdoutAfterCommitSubprocess$") //nolint:gosec // current test binary and fixed fixture
	cmd.Env = append(os.Environ(), "SYDGUARD_LEARN_PIPE_CHILD=1", "SYDGUARD_LEARN_CANDIDATE="+id)
	var stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = write, &stderr
	if err := cmd.Run(); err != nil || !strings.Contains(stderr.String(), "COMMITTED_REVIEW_RECOVERY") {
		t.Fatalf("broken stdout: %v %s", err, &stderr)
	}
	s, err = candidateStore()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	reviews, err := s.ReviewSummaries()
	if err != nil || len(reviews) != 1 || reviews[0].Status != "bound" {
		t.Fatalf("missing durable bound record: %+v %v", reviews, err)
	}
}
