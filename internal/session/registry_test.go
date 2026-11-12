package session

import (
	"fmt"
	"sync"
	"testing"
)

func TestDefaultNamesReleaseAndStaleIDs(t *testing.T) {
	registry := NewRegistry()
	first, err := registry.Register("/projects/my-app", "", []string{"claude"}, 10, "boot:100")
	if err != nil || first.Name != "my-app" {
		t.Fatalf("%+v %v", first, err)
	}
	second, err := registry.Register("/projects/my-app", "", []string{"pi"}, 11, "boot:101")
	if err != nil || second.Name != "my-app-1" {
		t.Fatalf("%+v %v", second, err)
	}
	if err := registry.Finish(first.ID, "different-start"); err == nil {
		t.Fatal("stale identity accepted")
	}
	if err := registry.Finish(first.ID, first.StartIdentity); err != nil {
		t.Fatal(err)
	}
	next, err := registry.Register("/projects/my-app", "", []string{"codex"}, 12, "boot:102")
	if err != nil || next.Name != "my-app" || next.ID == first.ID {
		t.Fatalf("name/opaque ID not safely reused: %+v %v", next, err)
	}
	if len(registry.List(false)) != 2 || len(registry.List(true)) != 3 {
		t.Fatal("active/history views differ incorrectly")
	}
}

func TestConcurrentNamesAndDefensiveCopies(t *testing.T) {
	registry := NewRegistry()
	var group sync.WaitGroup
	for i := 0; i < 50; i++ {
		group.Add(1)
		go func(n int) {
			defer group.Done()
			if _, err := registry.Register("/projects/app", "", []string{"pi"}, n+1, fmt.Sprintf("start:%d", n)); err != nil {
				t.Error(err)
			}
		}(i)
	}
	group.Wait()
	names := map[string]bool{}
	for _, session := range registry.List(false) {
		if names[session.Name] {
			t.Fatalf("duplicate %s", session.Name)
		}
		names[session.Name] = true
	}
	if len(names) != 50 {
		t.Fatalf("got %d", len(names))
	}
	view := registry.List(false)
	view[0].Command[0] = "mutated"
	for _, session := range registry.List(false) {
		if session.Command[0] == "mutated" {
			t.Fatal("returned view modified registry authority")
		}
	}
}
