package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Gobd/syd-guard/internal/learning"
)

// selectedProvenance is independent of a manual review receipt. A learned
// binding is never inferred from a hash or absence of a candidate record.
type selectedProvenance struct {
	Status string
	Detail string
}

type selectedProvenanceStoreKey struct{}

// The caller holds the private review lock through authorization/handoff.
// Missing evidence is manual/unknown, never proof of complete learning.
var lookupSelectedProvenance = func(ctx context.Context, project, name, revision string) (selectedProvenance, error) {
	store, ok := ctx.Value(selectedProvenanceStoreKey{}).(*learning.Store)
	if !ok {
		return selectedProvenance{}, errors.New("selected provenance requires private review authority")
	}
	candidate, reviewID, err := store.VerifyProvenance(project, name, revision)
	if errors.Is(err, learning.ErrReviewPending) {
		return selectedProvenance{Status: "pending"}, nil
	}
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, learning.ErrCurrentAuthorized) || errors.Is(err, learning.ErrHistoricalProvenance) {
		// Current-byte authorization after an uncertain operation is not an
		// acknowledged learning CAS. The separate exact-revision manual receipt
		// remains mandatory and no learning completeness/provenance is invented.
		return selectedProvenance{Status: "manual/unknown"}, nil
	}
	if err != nil {
		return selectedProvenance{}, err
	}
	return selectedProvenance{Status: "learned-reviewed", Detail: fmt.Sprintf("permission-check candidate=%s review=%s incomplete=%t reasons=%d file-checks=%d public-dials=%d; not successful-I/O or complete-coverage proof", candidate.ID, reviewID, candidate.Candidate.Incomplete, len(candidate.Candidate.Reasons), candidate.Candidate.Counts.FileChecks, candidate.Candidate.Counts.PublicDials)}, nil
}

func checkedSelectedProvenance(ctx context.Context, projectID, name, revision string) (selectedProvenance, error) {
	provenance, err := lookupSelectedProvenance(ctx, projectID, name, revision)
	if err != nil {
		return selectedProvenance{}, err
	}
	switch provenance.Status {
	case "manual/unknown":
		if provenance.Detail != "" {
			return selectedProvenance{}, errors.New("invalid unknown provenance detail")
		}
	case "learned-reviewed":
		if provenance.Detail == "" {
			return selectedProvenance{}, errors.New("learned provenance requires coverage description")
		}
	case "pending", "indeterminate":
		return selectedProvenance{}, errors.New("learned profile binding requires authenticated reconciliation before replay")
	default:
		return selectedProvenance{}, errors.New("unsupported profile provenance")
	}
	if len(provenance.Detail) > 1024 || !utf8.ValidString(provenance.Detail) || strings.IndexFunc(provenance.Detail, unicode.IsControl) >= 0 {
		return selectedProvenance{}, errors.New("invalid profile provenance description")
	}
	return provenance, nil
}
