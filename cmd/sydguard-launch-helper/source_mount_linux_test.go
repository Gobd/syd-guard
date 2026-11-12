//go:build linux

package main

import (
	"errors"
	"os"
	"testing"
)

func TestSourceMountsRejectBackingAliases(t *testing.T) {
	for _, tc := range []struct {
		name string
		root sourceMount
		fail bool
	}{
		{"same root filesystem", sourceMount{device: 1, mount: 10}, false},
		{"runtime bind of source subtree", sourceMount{device: 1, mount: 11}, true},
		{"home bind of source subtree", sourceMount{device: 1, mount: 12}, true},
		{"separate runtime filesystem", sourceMount{device: 2, mount: 20}, false},
		{"unknown mount identity", sourceMount{device: 1}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			identify := func(fd int) (sourceMount, error) {
				if fd == 1 {
					return sourceMount{device: 1, mount: 10}, nil
				}
				return tc.root, nil
			}
			if err := validateSourceMountsWith(1, []int{2}, identify); (err != nil) != tc.fail {
				t.Fatalf("unexpected mount validation outcome: %v", err)
			}
		})
	}
}

func TestSourceMountsPropagateIdentityFailure(t *testing.T) {
	failure := errors.New("statx unavailable")
	if err := validateSourceMountsWith(1, []int{2}, func(int) (sourceMount, error) { return sourceMount{}, failure }); !errors.Is(err, failure) {
		t.Fatalf("source identity failure was ignored: %v", err)
	}
	if err := validateSourceMountsWith(1, []int{2}, func(fd int) (sourceMount, error) {
		if fd == 1 {
			return sourceMount{device: 1, mount: 10}, nil
		}
		return sourceMount{}, failure
	}); !errors.Is(err, failure) {
		t.Fatalf("trusted directory identity failure was ignored: %v", err)
	}
}

func TestDirectoryMountUsesHeldDescriptor(t *testing.T) {
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	id, err := directoryMount(int(root.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if id.mount == 0 || id.device == 0 {
		t.Fatalf("missing descriptor mount identity: %+v", id)
	}
	if err := validateSourceMountsWith(int(root.Fd()), []int{int(root.Fd())}, directoryMount); err != nil {
		t.Fatal(err)
	}
}
