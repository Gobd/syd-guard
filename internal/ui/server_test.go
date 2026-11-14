package ui

import (
	"sync"
	"testing"
)

func TestSnapshotBackendConcurrentUpdates(t *testing.T) {
	u := &uiServer{}
	b := &backend{name: "test"}
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 10000 {
			u.mu.Lock()
			b.ok, b.err = true, ""
			u.mu.Unlock()
			u.mu.Lock()
			b.ok, b.err = false, "connecting"
			u.mu.Unlock()
		}
	})
	for range 10000 {
		snapshot := u.snapshotBackend(b)
		if snapshot.ok && snapshot.err != "" {
			t.Errorf("inconsistent backend snapshot: %+v", snapshot)
		}
	}
	wg.Wait()
}
