//go:build linux || darwin

package learning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/config"
	"golang.org/x/sys/unix"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp(home, ".sydguard-learning-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	store, err := OpenStore(filepath.Join(base, ".sydguard-private", "candidates"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestPrivateCandidateReviewProvenance(t *testing.T) {
	s := testStore(t)
	candidate := ProfileCandidate{Profile: config.Profile{Version: 1, Name: "default", Files: []config.FileRule{{Path: "/work/file", Access: []string{"read"}}}, Network: []config.NetworkRule{}}, Kind: "permission-check-candidate", Incomplete: true, Reasons: []string{"abnormal-exit"}, Counts: Counts{FileChecks: 3}}
	id, err := s.SaveCandidate(CandidateRecord{Project: "/work", Candidate: candidate, ExitCode: 1})
	if err != nil {
		t.Fatal(err)
	}
	values, err := s.Candidates()
	if err != nil || len(values) != 1 || values[0].Candidate.Counts.FileChecks != 3 {
		t.Fatalf("candidates: %+v %v", values, err)
	}
	data, err := json.Marshal(candidate.Profile)
	if err != nil {
		t.Fatal(err)
	}
	project, expected := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if _, err := s.BeginReview(id, project, "default", expected, data, false); err == nil {
		t.Fatal("accepted incomplete without acknowledgement")
	}
	var pending ReviewPending
	if err := s.WithReviewLock(func() error {
		var e error
		pending, e = s.BeginReview(id, project, "default", expected, data, true)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.VerifyProvenance(project, "default", pending.ReviewedRevision); !errors.Is(err, ErrReviewPending) {
		t.Fatalf("pending was not rejected: %v", err)
	}
	if _, err := s.BeginReview(id, project, "default", expected, data, true); err == nil {
		t.Fatal("unresolved review did not block retry")
	}
	if err := s.CompleteReview(pending.ID, "bound", project, "default", pending.ReviewedRevision, append(data, ' ')); err == nil {
		t.Fatal("mismatched bytes bound")
	}
	if err := s.CompleteReview(pending.ID, "bound", project, "default", pending.ReviewedRevision, data); err != nil {
		t.Fatal(err)
	}
	got, reviewID, err := s.VerifyProvenance(project, "default", pending.ReviewedRevision)
	if !errors.Is(err, ErrHistoricalProvenance) || reviewID != pending.ID || !got.Candidate.Incomplete || got.Candidate.Counts.FileChecks != 3 {
		t.Fatalf("historical provenance: %+v %s %v", got, reviewID, err)
	}
	if _, _, err := s.VerifyProvenance(project, "default", expected); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("wrong revision matched")
	}
	other := []byte(`{"version":1,"name":"default","files":[],"network":[]}`)
	later, err := s.BeginReview(id, project, "default", expected, other, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.VerifyProvenance(project, "default", pending.ReviewedRevision); !errors.Is(err, ErrReviewPending) {
		t.Fatalf("unresolved later review did not block existing binding: %v", err)
	}
	if err := s.AuthorizeCurrent(later.ID, project, "default", later.ReviewedRevision, other); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.VerifyProvenance(project, "default", later.ReviewedRevision); !errors.Is(err, ErrCurrentAuthorized) {
		t.Fatalf("manual authorization misclassified: %v", err)
	}
	if _, _, err := s.VerifyProvenance(project, "default", pending.ReviewedRevision); !errors.Is(err, ErrHistoricalProvenance) {
		t.Fatalf("old binding was not labelled historical after uncertain history: %v", err)
	}
}

func TestPrivateStoreRejectsSymlinkAndHardlink(t *testing.T) {
	s := testStore(t)
	candidate := ProfileCandidate{Profile: config.Profile{Version: 1, Name: "default", Files: []config.FileRule{}, Network: []config.NetworkRule{}}, Kind: "permission-check-candidate"}
	id, err := s.SaveCandidate(CandidateRecord{Project: "/work", Candidate: candidate})
	if err != nil {
		t.Fatal(err)
	}
	// Openat-based production reads check nlink; add an alias through the pinned directory.
	if err := unix.Linkat(s.dir, "candidate-"+id+".json", s.dir, "alias", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Candidate(id); err == nil {
		t.Fatal("accepted candidate record with multiple links")
	}
	if err := unix.Unlinkat(s.dir, "candidate-"+id+".json", 0); err != nil {
		t.Fatal(err)
	}
	if err := unix.Symlinkat("alias", s.dir, "candidate-"+id+".json"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Candidate(id); err == nil {
		t.Fatal("accepted symlinked candidate record")
	}
}

func TestPrivateReviewLockCancellation(t *testing.T) {
	s := testStore(t)
	fd, err := unix.Openat(s.dir, "review.lock", unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Flock(fd, unix.LOCK_UN) }()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	called := false
	err = s.WithReviewLockContext(ctx, func() error { called = true; return nil })
	if !errors.Is(err, context.DeadlineExceeded) || called {
		t.Fatalf("lock cancellation: called=%t err=%v", called, err)
	}
}

func TestPrivateReviewPublicationCrash(t *testing.T) {
	if point := os.Getenv("SYDGUARD_PUBLICATION_CRASH_POINT"); point != "" {
		s, err := OpenStore(os.Getenv("SYDGUARD_PUBLICATION_STORE"))
		if err != nil {
			os.Exit(2)
		}
		s.publicationHook = func(stage string) error {
			if stage == point {
				os.Exit(77)
			}
			return nil
		}
		_ = s.writeNew("review-0123456789abcdef0123456789abcdef.json", map[string]string{"value": "complete"})
		os.Exit(3)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, point := range []string{"written", "synced", "published"} {
		t.Run(point, func(t *testing.T) {
			base, err := os.MkdirTemp(home, ".sg-publication-")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = os.RemoveAll(base) }()
			path := filepath.Join(base, ".sydguard-private", "candidates")
			s, err := OpenStore(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = s.Close() }()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(executable, "-test.run=^TestPrivateReviewPublicationCrash$") //nolint:gosec // current test executable and fixed fixture
			cmd.Env = append(os.Environ(), "SYDGUARD_PUBLICATION_CRASH_POINT="+point, "SYDGUARD_PUBLICATION_STORE="+path)
			if err := cmd.Run(); err == nil {
				t.Fatal("child did not crash")
			}
			var record map[string]string
			err = s.read("review-0123456789abcdef0123456789abcdef.json", &record)
			if point != "published" {
				if !errors.Is(err, unix.ENOENT) {
					t.Fatalf("unpublished final visible: %v", err)
				}
			} else if err != nil || record["value"] != "complete" {
				t.Fatalf("published final torn: %+v %v", record, err)
			}
		})
	}
}

func TestPrivateCandidateListingIgnoresReviewFileCount(t *testing.T) {
	if _, err := boundedStoreNames(make([]string, maxStoreEntries+1)); err == nil {
		t.Fatal("overall scan was not bounded")
	}
	s := testStore(t)
	candidate := ProfileCandidate{Profile: config.Profile{Version: 1, Name: "default", Files: []config.FileRule{}, Network: []config.NetworkRule{}}, Kind: "permission-check-candidate"}
	if _, err := s.SaveCandidate(CandidateRecord{Project: "/work", Candidate: candidate}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxCandidates+1; i++ {
		name := fmt.Sprintf("result-%032x.json", i)
		fd, err := unix.Openat(s.dir, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_ = unix.Close(fd)
	}
	values, err := s.Candidates()
	if err != nil || len(values) != 1 {
		t.Fatalf("candidate listing incorrectly counted review files: %d %v", len(values), err)
	}
	if _, err := s.reviewNames(); err == nil {
		t.Fatal("review result count was not bounded independently")
	}
}

func TestPrivateReviewPublicationFailurePreservesPendingOrComplete(t *testing.T) {
	s := testStore(t)
	candidate := ProfileCandidate{Profile: config.Profile{Version: 1, Name: "default", Files: []config.FileRule{}, Network: []config.NetworkRule{}}, Kind: "permission-check-candidate"}
	id, err := s.SaveCandidate(CandidateRecord{Project: "/work", Candidate: candidate})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(candidate.Profile)
	if err != nil {
		t.Fatal(err)
	}
	project, expected := strings.Repeat("a", 64), strings.Repeat("b", 64)
	pending, err := s.BeginReview(id, project, "default", expected, data, false)
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("injected publication failure")
	s.publicationHook = func(stage string) error {
		if stage == "synced" {
			return failure
		}
		return nil
	}
	if err := s.CompleteReview(pending.ID, "bound", project, "default", pending.ReviewedRevision, data); !errors.Is(err, failure) {
		t.Fatalf("missing fault: %v", err)
	}
	if _, result, err := s.Review(pending.ID); err != nil || result != nil {
		t.Fatalf("pending not recoverable: %+v %v", result, err)
	}
	s.publicationHook = func(stage string) error {
		if stage == "published" {
			return failure
		}
		return nil
	}
	if err := s.CompleteReview(pending.ID, "bound", project, "default", pending.ReviewedRevision, data); !errors.Is(err, failure) {
		t.Fatalf("missing post-publication fault: %v", err)
	}
	if _, result, err := s.Review(pending.ID); err != nil || result == nil || result.Status != "bound" {
		t.Fatalf("published result not complete: %+v %v", result, err)
	}
	s.publicationHook = nil
	if err := s.writeNew("result-"+pending.ID+".json", map[string]string{"replace": "forbidden"}); !errors.Is(err, unix.EEXIST) {
		t.Fatalf("replacement allowed: %v", err)
	}
}

func TestVerifyProvenanceOrdinaryABAAndRepeatedIdenticalReviews(t *testing.T) {
	s := testStore(t)
	profile := config.Profile{Version: 1, Name: "default", Files: []config.FileRule{}, Network: []config.NetworkRule{}}
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	project, expected := strings.Repeat("a", 64), strings.Repeat("b", 64)
	var first ReviewPending
	for i := range 2 {
		candidate := ProfileCandidate{Profile: profile, Kind: "permission-check-candidate", Counts: Counts{FileChecks: uint64(i + 1)}}
		id, err := s.SaveCandidate(CandidateRecord{Project: "/work", Candidate: candidate})
		if err != nil {
			t.Fatal(err)
		}
		pending, err := s.BeginReview(id, project, "default", expected, data, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.CompleteReview(pending.ID, "bound", project, "default", pending.ReviewedRevision, data); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = pending
			// Ordinary managed writes may change A to B and back to A without
			// touching this store. Even one match cannot establish current origin.
			got, reviewID, err := s.VerifyProvenance(project, "default", pending.ReviewedRevision)
			if !errors.Is(err, ErrHistoricalProvenance) || reviewID != pending.ID || got.Candidate.Counts.FileChecks != 1 {
				t.Fatalf("ABA claimed current provenance: %+v %s %v", got, reviewID, err)
			}
		}
	}
	got, reviewID, err := s.VerifyProvenance(project, "default", first.ReviewedRevision)
	if !errors.Is(err, ErrHistoricalProvenance) || reviewID != "" || got.ID != "" {
		t.Fatalf("repeated matches selected an arbitrary review: %+v %s %v", got, reviewID, err)
	}
	reviews, err := s.ReviewSummaries()
	if err != nil || len(reviews) != 2 {
		t.Fatalf("historical reviews not retained: %+v %v", reviews, err)
	}
	for _, summary := range reviews {
		pending, result, err := s.Review(summary.ID)
		if err != nil || result == nil || result.Status != "bound" {
			t.Fatalf("review missing: %+v %v", summary, err)
		}
		if _, err := s.Candidate(pending.CandidateID); err != nil {
			t.Fatalf("original candidate missing: %v", err)
		}
	}
}

func TestSaveCandidateIndependentOfReviewLock(t *testing.T) {
	s := testStore(t)
	fd, err := unix.Openat(s.dir, "review.lock", unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Flock(fd, unix.LOCK_UN) }()
	candidate := ProfileCandidate{Profile: config.Profile{Version: 1, Name: "default", Files: []config.FileRule{}, Network: []config.NetworkRule{}}, Kind: "permission-check-candidate"}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := s.SaveCandidateContext(ctx, CandidateRecord{Project: "/work", Candidate: candidate}); err != nil {
		t.Fatalf("review lock blocked candidate publication: %v", err)
	}
}

func TestSaveCandidateLockHonorsCancellation(t *testing.T) {
	s := testStore(t)
	fd, err := unix.Openat(s.dir, "candidate.lock", unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	candidate := ProfileCandidate{Profile: config.Profile{Version: 1, Name: "default", Files: []config.FileRule{}, Network: []config.NetworkRule{}}, Kind: "permission-check-candidate"}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	if _, err := s.SaveCandidateContext(ctx, CandidateRecord{Project: "/work", Candidate: candidate}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("candidate lock cancellation: %v", err)
	}
	if err := unix.Flock(fd, unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	values, err := s.Candidates()
	if err != nil || len(values) != 0 {
		t.Fatalf("canceled publication persisted: %+v %v", values, err)
	}
	if _, err := s.SaveCandidate(CandidateRecord{Project: "/work", Candidate: candidate}); err != nil {
		t.Fatalf("corrected candidate retry: %v", err)
	}
}

func TestSaveCandidateConcurrentPublication(t *testing.T) {
	s := testStore(t)
	candidate := ProfileCandidate{Profile: config.Profile{Version: 1, Name: "default", Files: []config.FileRule{}, Network: []config.NetworkRule{}}, Kind: "permission-check-candidate"}
	results := make(chan error, 32)
	for range 32 {
		go func() {
			_, err := s.SaveCandidate(CandidateRecord{Project: "/work", Candidate: candidate})
			results <- err
		}()
	}
	var failures []error
	for range 32 {
		if err := <-results; err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) != 0 {
		t.Fatalf("concurrent publication errors: %v", failures)
	}
	values, err := s.Candidates()
	if err != nil || len(values) != 32 {
		t.Fatalf("candidate publication lost entries: %d %v", len(values), err)
	}
}

func TestSaveCandidateDefaultLockWaitIsBounded(t *testing.T) {
	s := testStore(t)
	fd, err := unix.Openat(s.dir, "candidate.lock", unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Flock(fd, unix.LOCK_UN) }()
	candidate := ProfileCandidate{Profile: config.Profile{Version: 1, Name: "default", Files: []config.FileRule{}, Network: []config.NetworkRule{}}, Kind: "permission-check-candidate"}
	started := time.Now()
	_, err = s.SaveCandidate(CandidateRecord{Project: "/work", Candidate: candidate})
	elapsed := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) || elapsed < 2*time.Second || elapsed > 5*time.Second {
		t.Fatalf("candidate lock wait=%v err=%v", elapsed, err)
	}
}
