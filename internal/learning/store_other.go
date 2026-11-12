//go:build !linux && !darwin

package learning

import (
	"context"
	"errors"
)

type CandidateRecord struct {
	ID          string           `json:"id"`
	Project     string           `json:"project"`
	Candidate   ProfileCandidate `json:"candidate"`
	ExitCode    int              `json:"exit_code"`
	Cancelled   bool             `json:"cancelled"`
	Signal      string           `json:"signal,omitempty"`
	LaunchError bool             `json:"launch_error"`
}
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
	Status          string `json:"status"`
	ProjectID       string `json:"project_id"`
	Name            string `json:"name"`
	Revision        string `json:"revision"`
	OperationStatus string `json:"operation_status,omitempty"`
	CurrentBytes    []byte `json:"current_bytes,omitempty"`
}
type Store struct{}

var errStoreUnsupported = errors.New("private candidate store unsupported on this platform")

func OpenStore(string) (*Store, error)                       { return nil, errStoreUnsupported }
func (*Store) Close() error                                  { return nil }
func (*Store) SaveCandidate(CandidateRecord) (string, error) { return "", errStoreUnsupported }
func (*Store) Candidate(string) (CandidateRecord, error) {
	return CandidateRecord{}, errStoreUnsupported
}

func (*Store) Candidates() ([]CandidateRecord, error) { return nil, errStoreUnsupported }

func (*Store) WithReviewLock(func() error) error { return errStoreUnsupported }

func (*Store) WithReviewLockContext(context.Context, func() error) error { return errStoreUnsupported }

func (*Store) BeginReview(string, string, string, string, []byte, bool) (ReviewPending, error) {
	return ReviewPending{}, errStoreUnsupported
}

func (*Store) Review(string) (ReviewPending, *ReviewResult, error) {
	return ReviewPending{}, nil, errStoreUnsupported
}

func (*Store) CompleteReview(string, string, string, string, string, []byte) error {
	return errStoreUnsupported
}

func (*Store) AuthorizeCurrent(string, string, string, string, []byte) error {
	return errStoreUnsupported
}

func (*Store) VerifyProvenance(string, string, string) (CandidateRecord, string, error) {
	return CandidateRecord{}, "", errStoreUnsupported
}

type ReviewSummary struct {
	ID               string `json:"id"`
	CandidateID      string `json:"candidate_id"`
	ProjectID        string `json:"project_id"`
	Name             string `json:"name"`
	ReviewedRevision string `json:"reviewed_revision"`
	Status           string `json:"status"`
	OperationStatus  string `json:"operation_status"`
}

func (*Store) ReviewSummaries() ([]ReviewSummary, error) { return nil, errStoreUnsupported }
