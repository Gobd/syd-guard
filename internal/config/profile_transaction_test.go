package config

import (
	"errors"
	"testing"
)

func TestPrepareProfileReplacementRevisionConflict(t *testing.T) {
	initial := []byte(`{"version":1,"name":"build","files":[],"network":[]}`)
	base, err := ParseProfileSnapshot("build", initial)
	if err != nil {
		t.Fatal(err)
	}
	next, err := MergeProfile(base, nil, []NetworkRule{{Host: "example.com", Port: 443, Transport: "tcp"}})
	if err != nil {
		t.Fatal(err)
	}
	value, err := PrepareProfileReplacement("build", base.Revision(), initial, next)
	if err != nil {
		t.Fatal(err)
	}
	value[0] = 'x'
	if next.Bytes()[0] == 'x' {
		t.Fatal("replacement leaked snapshot memory")
	}
	_, err = PrepareProfileReplacement("build", base.Revision(), next.Bytes(), next)
	if !errors.Is(err, ErrProfileConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	if _, err := PrepareProfileReplacement("default", base.Revision(), initial, next); err == nil {
		t.Fatal("accepted another profile")
	}
	if _, err := PrepareProfileReplacement("build", "", initial, next); err == nil {
		t.Fatal("accepted absent revision")
	}
}
