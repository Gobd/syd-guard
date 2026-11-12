package config

import (
	"errors"
	"fmt"
)

// ErrProfileConflict indicates the reviewed base no longer matches the store.
var ErrProfileConflict = errors.New("profile revision conflict")

// PrepareProfileReplacement compares the current bytes to the reviewed base
// and returns an independent validated replacement. This is not an atomic store:
// the managed writer must serialize the read, this check, and atomic rename,
// and prevent all other writers from modifying or replacing the directory.
func PrepareProfileReplacement(name, expectedRevision string, current []byte, replacement ProfileSnapshot) ([]byte, error) {
	if expectedRevision == "" || replacement.revision == "" {
		return nil, fmt.Errorf("replacement requires reviewed revisions")
	}
	before, err := ParseProfileSnapshot(name, current)
	if err != nil {
		return nil, err
	}
	if before.Revision() != expectedRevision {
		return nil, ErrProfileConflict
	}
	after, err := ParseProfileSnapshot(name, replacement.Bytes())
	if err != nil {
		return nil, err
	}
	return after.Bytes(), nil
}
