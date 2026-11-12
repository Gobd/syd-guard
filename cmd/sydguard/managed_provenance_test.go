package main

import (
	"context"
	"errors"
	"testing"
)

func TestSelectedProvenanceRejectsUncertainBindings(t *testing.T) {
	old := lookupSelectedProvenance
	defer func() { lookupSelectedProvenance = old }()
	for _, tc := range []struct {
		status, detail string
		accepted       bool
	}{
		{"manual/unknown", "", true},
		{"manual/unknown", "claims learning", false},
		{"learned-reviewed", "permission-check candidate; incomplete coverage", true},
		{"learned-reviewed", "", false},
		{"pending", "", false},
		{"indeterminate", "", false},
		{"complete", "", false},
		{"learned-reviewed", "line\nforgery", false},
	} {
		t.Run(tc.status+tc.detail, func(t *testing.T) {
			lookupSelectedProvenance = func(_ context.Context, project, name, revision string) (selectedProvenance, error) {
				if project != "project" || name != "name" || revision != "revision" {
					t.Fatal("binding not forwarded")
				}
				return selectedProvenance{Status: tc.status, Detail: tc.detail}, nil
			}
			_, err := checkedSelectedProvenance(context.Background(), "project", "name", "revision")
			if (err == nil) != tc.accepted {
				t.Fatalf("provenance check: %v", err)
			}
		})
	}
	lookupSelectedProvenance = func(context.Context, string, string, string) (selectedProvenance, error) {
		return selectedProvenance{}, errors.New("lookup failed")
	}
	if _, err := checkedSelectedProvenance(context.Background(), "project", "name", "revision"); err == nil {
		t.Fatal("lookup failure ignored")
	}
}
