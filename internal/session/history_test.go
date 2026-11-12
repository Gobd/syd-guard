package session

import "testing"

func TestHistoryIsBoundedWithoutDiscardingActiveSession(t *testing.T) {
	registry := NewRegistry()
	active, err := registry.Register("/projects/active", "", []string{"pi"}, 1, "boot:active")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 300; i++ {
		value, err := registry.Register("/projects/ended", "", []string{"pi"}, i+2, "boot:ended")
		if err != nil {
			t.Fatal(err)
		}
		if err := registry.Finish(value.ID, value.StartIdentity); err != nil {
			t.Fatal(err)
		}
	}
	if len(registry.List(true)) != 257 {
		t.Fatalf("history grew beyond bound: %d", len(registry.List(true)))
	}
	if value, ok := registry.Get(active.ID); !ok || value.State != Running {
		t.Fatal("active authority was discarded")
	}
}
