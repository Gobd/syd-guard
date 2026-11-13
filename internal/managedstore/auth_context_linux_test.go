//go:build linux

package managedstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// This tests the real lock wait using only ordinary, test-owned files; it does
// not weaken Store's production root ownership checks or construct a registry.
func TestLockWithContextHeldOrdinaryFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	held, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	waiting, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer waiting.Close()
	if err := unix.Flock(int(held.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = lockWithContext(ctx, int(waiting.Fd()))
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("held lock result: %v", err)
	}
	if elapsed > time.Second {
		t.Fatalf("context wait exceeded bound: %s", elapsed)
	}
	if err := unix.Flock(int(held.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	cancelled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if err := lockWithContext(cancelled, int(waiting.Fd())); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context: %v", err)
	}
	if err := lockWithContext(context.Background(), int(waiting.Fd())); err != nil {
		t.Fatal(err)
	}
}
