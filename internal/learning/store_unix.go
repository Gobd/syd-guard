//go:build linux || darwin

package learning

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Gobd/syd-guard/internal/config"

	"golang.org/x/sys/unix"
)

// CandidateRecord is private review evidence, not an authorization or profile.
type CandidateRecord struct {
	ID          string           `json:"id"`
	Project     string           `json:"project"`
	Candidate   ProfileCandidate `json:"candidate"`
	ExitCode    int              `json:"exit_code"`
	Cancelled   bool             `json:"cancelled"`
	Signal      string           `json:"signal,omitempty"`
	LaunchError bool             `json:"launch_error"`
}

// Store holds a pinned descriptor for an operator-owned private directory.
// Its input is the reserved .sydguard-private/candidates directory, not a
// project path. No method activates a candidate.
type Store struct {
	dir             int
	publicationHook func(string) error // test-only fault injection; nil in production
}

func OpenStore(path string) (*Store, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "candidates" || filepath.Base(filepath.Dir(path)) != ".sydguard-private" {
		return nil, errors.New("invalid candidate authority path")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		if i >= len(parts)-2 {
			if err = unix.Mkdirat(fd, part, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
				_ = unix.Close(fd)
				return nil, err
			}
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if e != nil {
			return nil, e
		}
		fd = next
		var st unix.Stat_t
		if e = unix.Fstat(fd, &st); e != nil {
			_ = unix.Close(fd)
			return nil, e
		}
		if st.Mode&0o022 != 0 || (st.Uid != 0 && int(st.Uid) != os.Geteuid()) || (i >= len(parts)-2 && (int(st.Uid) != os.Geteuid() || st.Mode&0o7777 != 0o700)) {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("unsafe candidate authority ancestor")
		}
	}
	return &Store{dir: fd}, nil
}

func (s *Store) Close() error { return unix.Close(s.dir) }

func validID(id string) bool {
	if len(id) != 32 || strings.ToLower(id) != id {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func (s *Store) writeNew(name string, value any) error {
	data, err := json.Marshal(value)
	if err != nil || len(data) > 2*1024*1024 {
		return errors.New("invalid or oversized private record")
	}
	id, err := randomID()
	if err != nil {
		return err
	}
	temporary := ".stage-" + id
	fd, err := unix.Openat(s.dir, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), temporary)
	defer func() { _ = f.Close(); _ = unix.Unlinkat(s.dir, temporary, 0) }()
	if err = f.Chmod(0o600); err == nil {
		_, err = f.Write(append(data, '\n'))
	}
	if err == nil {
		err = s.publicationPoint("written")
	}
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = s.publicationPoint("synced")
	}
	if err == nil {
		err = f.Close()
	}
	if err == nil {
		err = publishNoReplace(s.dir, temporary, name)
	}
	if err == nil {
		err = s.publicationPoint("published")
	}
	if err == nil {
		err = unix.Fsync(s.dir)
	}
	return err
}

func (s *Store) publicationPoint(point string) error {
	if s.publicationHook != nil {
		return s.publicationHook(point)
	}
	return nil
}

func (s *Store) read(name string, value any) error {
	fd, err := unix.Openat(s.dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), name)
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o7777 != 0o600 || int(st.Uid) != os.Geteuid() || st.Nlink != 1 || st.Size > 2*1024*1024 {
		return errors.New("unsafe private record")
	}
	data, err := io.ReadAll(io.LimitReader(f, 2*1024*1024+1))
	if err != nil || len(data) > 2*1024*1024 {
		return errors.New("invalid private record")
	}
	if _, err := decodeObject(data); err != nil {
		return errors.New("invalid private record structure")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err = d.Decode(value); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing private record data")
	}
	return nil
}

func validCandidate(record CandidateRecord) bool {
	candidate := record.Candidate
	if !filepath.IsAbs(record.Project) || filepath.Clean(record.Project) != record.Project || candidate.Kind != "permission-check-candidate" || candidate.Incomplete != (len(candidate.Reasons) != 0) || record.ExitCode < 0 || (record.ExitCode != 0 || record.Cancelled || record.Signal != "" || record.LaunchError) && !candidate.Incomplete {
		return false
	}
	for _, reason := range candidate.Reasons {
		if reason == "" {
			return false
		}
	}
	data, err := json.Marshal(candidate.Profile)
	if err != nil {
		return false
	}
	_, err = config.ParseProfileSnapshot(candidate.Profile.Name, data)
	return err == nil
}

func (s *Store) SaveCandidate(record CandidateRecord) (string, error) {
	if record.ID != "" || !validCandidate(record) {
		return "", errors.New("invalid candidate")
	}
	var id string
	err := s.WithReviewLock(func() error {
		names, err := s.storeNames()
		if err != nil {
			return err
		}
		count := 0
		for _, name := range names {
			if strings.HasPrefix(name, "candidate-") && strings.HasSuffix(name, ".json") {
				count++
			}
		}
		if count >= maxCandidates {
			return errors.New("candidate count limit reached")
		}
		id, err = randomID()
		if err != nil {
			return err
		}
		record.ID = id
		return s.writeNew("candidate-"+id+".json", record)
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

func (s *Store) Candidate(id string) (CandidateRecord, error) {
	var record CandidateRecord
	if !validID(id) {
		return record, errors.New("invalid candidate ID")
	}
	if err := s.read("candidate-"+id+".json", &record); err != nil {
		return record, err
	}
	if record.ID != id || !validCandidate(record) {
		return CandidateRecord{}, errors.New("invalid candidate record")
	}
	return record, nil
}

const (
	maxCandidates   = 4096
	maxReviews      = 4096
	maxStoreEntries = 16384
)

func (s *Store) storeNames() ([]string, error) {
	fd, err := unix.Openat(s.dir, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "candidate authority")
	defer func() { _ = f.Close() }()
	names, err := f.Readdirnames(maxStoreEntries + 1)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return boundedStoreNames(names)
}

func boundedStoreNames(names []string) ([]string, error) {
	if len(names) > maxStoreEntries {
		return nil, errors.New("candidate authority scan limit exceeded")
	}
	sort.Strings(names)
	return names, nil
}

func (s *Store) Candidates() ([]CandidateRecord, error) {
	names, err := s.storeNames()
	if err != nil {
		return nil, err
	}
	result := []CandidateRecord{}
	for _, name := range names {
		if !strings.HasPrefix(name, "candidate-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(name, "candidate-"), ".json")
		if len(result) >= maxCandidates {
			return nil, errors.New("candidate count limit exceeded")
		}
		record, err := s.Candidate(id)
		if err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	return result, nil
}

// ReviewPending is written durably before invoking managed CAS. An absent
// result is deliberately indeterminate, not evidence that CAS did not commit.
type ReviewPending struct {
	ID                 string `json:"id"`
	CandidateID        string `json:"candidate_id"`
	ProjectID          string `json:"project_id"`
	Name               string `json:"name"`
	ExpectedRevision   string `json:"expected_revision"`
	ReviewedRevision   string `json:"reviewed_revision"`
	ReviewedBytes      []byte `json:"reviewed_bytes"`
	IncompleteAccepted bool   `json:"incomplete_accepted"`
}

type ReviewResult struct {
	ID              string `json:"id"`
	Status          string `json:"status"` // bound, rejected or separately current-authorized
	ProjectID       string `json:"project_id"`
	Name            string `json:"name"`
	Revision        string `json:"revision"`
	OperationStatus string `json:"operation_status,omitempty"`
	CurrentBytes    []byte `json:"current_bytes,omitempty"`
}

func validDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// WithReviewLock serializes pending checks and mutations across CLI processes.
func (s *Store) WithReviewLock(fn func() error) error {
	return s.WithReviewLockContext(context.Background(), fn)
}

// WithReviewLockContext honors cancellation before acquiring review authority.
func (s *Store) WithReviewLockContext(ctx context.Context, fn func() error) error {
	fd, err := unix.Openat(s.dir, "review.lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "review.lock")
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o7777 != 0o600 || int(st.Uid) != os.Geteuid() || st.Nlink != 1 {
		return errors.New("unsafe review lock")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	defer func() { _ = unix.Flock(fd, unix.LOCK_UN) }()
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn()
}

func (s *Store) reviewNames() ([]string, error) {
	names, err := s.storeNames()
	if err != nil {
		return nil, err
	}
	reviews, results := 0, 0
	for _, name := range names {
		if strings.HasPrefix(name, "review-") && strings.HasSuffix(name, ".json") {
			reviews++
		}
		if strings.HasPrefix(name, "result-") && strings.HasSuffix(name, ".json") {
			results++
		}
	}
	if reviews > maxReviews || results > maxReviews {
		return nil, errors.New("review count limit exceeded")
	}
	return names, nil
}

func (s *Store) Review(id string) (ReviewPending, *ReviewResult, error) {
	var pending ReviewPending
	if !validID(id) {
		return pending, nil, errors.New("invalid review ID")
	}
	if err := s.read("review-"+id+".json", &pending); err != nil {
		return pending, nil, err
	}
	if pending.ID != id || !validID(pending.CandidateID) || !validDigest(pending.ProjectID) || !validDigest(pending.ExpectedRevision) || !validDigest(pending.ReviewedRevision) {
		return pending, nil, errors.New("invalid pending review")
	}
	snapshot, err := config.ParseProfileSnapshot(pending.Name, pending.ReviewedBytes)
	if err != nil || snapshot.Revision() != pending.ReviewedRevision {
		return pending, nil, errors.New("invalid reviewed profile bytes")
	}
	candidate, err := s.Candidate(pending.CandidateID)
	if err != nil || candidate.Candidate.Incomplete && !pending.IncompleteAccepted {
		return pending, nil, errors.New("invalid review candidate binding")
	}
	var result ReviewResult
	err = s.read("result-"+id+".json", &result)
	if errors.Is(err, unix.ENOENT) {
		return pending, nil, nil
	}
	if err != nil {
		return pending, nil, err
	}
	if result.ID != id || result.ProjectID != pending.ProjectID || result.Name != pending.Name {
		return pending, nil, errors.New("invalid review result")
	}
	switch result.Status {
	case "bound":
		if result.Revision != pending.ReviewedRevision || len(result.CurrentBytes) != 0 || result.OperationStatus != "" {
			return pending, nil, errors.New("invalid bound review")
		}
	case "rejected":
		if result.Revision != "" || len(result.CurrentBytes) != 0 || result.OperationStatus != "" {
			return pending, nil, errors.New("invalid rejected review")
		}
	case "current-authorized":
		current, err := config.ParseProfileSnapshot(result.Name, result.CurrentBytes)
		if err != nil || current.Revision() != result.Revision || result.OperationStatus != "unknown" {
			return pending, nil, errors.New("invalid current authorization")
		}
	default:
		return pending, nil, errors.New("invalid review status")
	}
	return pending, &result, nil
}

// BeginReview must be called with WithReviewLock. It preserves the complete
// original candidate separately from the exact edited profile bytes.
func (s *Store) BeginReview(candidateID, projectID, name, expected string, data []byte, acceptIncomplete bool) (ReviewPending, error) {
	var pending ReviewPending
	candidate, err := s.Candidate(candidateID)
	if err != nil {
		return pending, err
	}
	if candidate.Candidate.Incomplete && !acceptIncomplete {
		return pending, errors.New("incomplete candidate requires explicit acknowledgement")
	}
	if !validDigest(projectID) || !validDigest(expected) {
		return pending, errors.New("invalid managed project ID or revision")
	}
	snapshot, err := config.ParseProfileSnapshot(name, data)
	if err != nil {
		return pending, err
	}
	names, err := s.reviewNames()
	if err != nil {
		return pending, err
	}
	reviewCount := 0
	for _, filename := range names {
		if !strings.HasPrefix(filename, "review-") || !strings.HasSuffix(filename, ".json") {
			continue
		}
		reviewCount++
		id := strings.TrimSuffix(strings.TrimPrefix(filename, "review-"), ".json")
		other, result, err := s.Review(id)
		if err != nil {
			return pending, err
		}
		if other.ProjectID == projectID && other.Name == name && result == nil {
			return pending, errors.New("unresolved prior review; authenticate and reconcile before retry")
		}
	}
	if reviewCount >= maxReviews {
		return pending, errors.New("review count limit reached")
	}
	id, err := randomID()
	if err != nil {
		return pending, err
	}
	pending = ReviewPending{ID: id, CandidateID: candidateID, ProjectID: projectID, Name: name, ExpectedRevision: expected, ReviewedRevision: snapshot.Revision(), ReviewedBytes: snapshot.Bytes(), IncompleteAccepted: acceptIncomplete}
	if err := s.writeNew("review-"+id+".json", pending); err != nil {
		return ReviewPending{}, err
	}
	return pending, nil
}

// CompleteReview must be called with WithReviewLock. A bound result requires an
// authenticated helper snapshot with the exact pending tuple and bytes.
func (s *Store) CompleteReview(id, status, projectID, name, revision string, data []byte) error {
	pending, existing, err := s.Review(id)
	if err != nil {
		return err
	}
	if existing != nil {
		return errors.New("review already resolved")
	}
	if projectID != pending.ProjectID || name != pending.Name {
		return errors.New("review tuple mismatch")
	}
	if status == "bound" {
		if revision != pending.ReviewedRevision || !bytes.Equal(data, pending.ReviewedBytes) {
			return errors.New("reviewed bytes or revision mismatch")
		}
	} else if status != "rejected" || revision != "" || len(data) != 0 {
		return errors.New("invalid review result")
	}
	return s.writeNew("result-"+id+".json", ReviewResult{ID: id, Status: status, ProjectID: projectID, Name: name, Revision: revision})
}

// AuthorizeCurrent records a separately operator-reviewed current snapshot. It
// never asserts that the indeterminate CAS committed. Caller holds review lock.
func (s *Store) AuthorizeCurrent(id, projectID, name, revision string, data []byte) error {
	pending, existing, err := s.Review(id)
	if err != nil {
		return err
	}
	if existing != nil {
		return errors.New("review already resolved")
	}
	if projectID != pending.ProjectID || name != pending.Name {
		return errors.New("review tuple mismatch")
	}
	current, err := config.ParseProfileSnapshot(name, data)
	if err != nil || current.Revision() != revision {
		return errors.New("current snapshot revision mismatch")
	}
	return s.writeNew("result-"+id+".json", ReviewResult{ID: id, Status: "current-authorized", ProjectID: projectID, Name: name, Revision: revision, OperationStatus: "unknown", CurrentBytes: current.Bytes()})
}

// VerifyProvenance returns a full original envelope only for a matching bound
// helper tuple and exact profile revision. The caller must hold WithReviewLock
// across this check and its authorization handoff, and independently authenticate
// the helper snapshot and hash its exact bytes. ErrReviewPending is a hard deny;
// os.ErrNotExist means unknown provenance, never complete learning coverage.
func (s *Store) VerifyProvenance(projectID, name, revision string) (CandidateRecord, string, error) {
	var candidate CandidateRecord
	if !validDigest(projectID) || !validDigest(revision) || config.ProfileName(name) != nil {
		return candidate, "", errors.New("invalid provenance tuple")
	}
	names, err := s.reviewNames()
	if err != nil {
		return candidate, "", err
	}
	var foundID, foundCandidate string
	currentAuthorized, hasUncertainHistory := false, false
	for _, filename := range names {
		if !strings.HasPrefix(filename, "review-") || !strings.HasSuffix(filename, ".json") {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(filename, "review-"), ".json")
		pending, result, err := s.Review(id)
		if err != nil {
			return candidate, "", err
		}
		if pending.ProjectID != projectID || pending.Name != name {
			continue
		}
		if result == nil {
			return candidate, "", ErrReviewPending
		}
		if result.Status == "current-authorized" {
			hasUncertainHistory = true
			if result.Revision == revision {
				currentAuthorized = true
			}
		}
		if pending.ReviewedRevision == revision && result.Status == "bound" {
			foundID, foundCandidate = id, pending.CandidateID
		}
	}
	if currentAuthorized {
		return candidate, "", ErrCurrentAuthorized
	}
	// Content hashes can return to an earlier bound revision after an
	// independently authorized uncertain operation. Do not infer provenance
	// from an older binding when ordering cannot be established.
	if hasUncertainHistory {
		return candidate, "", os.ErrNotExist
	}
	if foundID == "" {
		return candidate, "", os.ErrNotExist
	}
	candidate, err = s.Candidate(foundCandidate)
	return candidate, foundID, err
}

// ReviewSummary exposes recoverable IDs without exporting reviewed profile bytes.
type ReviewSummary struct {
	ID               string `json:"id"`
	CandidateID      string `json:"candidate_id"`
	ProjectID        string `json:"project_id"`
	Name             string `json:"name"`
	ReviewedRevision string `json:"reviewed_revision"`
	Status           string `json:"status"`
	OperationStatus  string `json:"operation_status"`
}

func (s *Store) ReviewSummaries() ([]ReviewSummary, error) {
	names, err := s.reviewNames()
	if err != nil {
		return nil, err
	}
	values := []ReviewSummary{}
	for _, filename := range names {
		if !strings.HasPrefix(filename, "review-") || !strings.HasSuffix(filename, ".json") {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(filename, "review-"), ".json")
		pending, result, err := s.Review(id)
		if err != nil {
			return nil, err
		}
		status, operationStatus := "unknown", "unknown"
		if result != nil {
			status = result.Status
			switch result.Status {
			case "bound":
				operationStatus = "acknowledged"
			case "rejected":
				operationStatus = "rejected"
			}
		}
		values = append(values, ReviewSummary{ID: id, CandidateID: pending.CandidateID, ProjectID: pending.ProjectID, Name: pending.Name, ReviewedRevision: pending.ReviewedRevision, Status: status, OperationStatus: operationStatus})
	}
	return values, nil
}
