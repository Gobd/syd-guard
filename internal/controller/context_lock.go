package controller

import (
	"context"
	"sync"
	"time"
)

// lockContext never leaves a goroutine waiting to acquire authority after its
// caller has canceled. Only short polling waits, bounded by the caller, occur.
func lockContext(ctx context.Context, mutex *sync.Mutex) error {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if mutex.TryLock() {
			if err := ctx.Err(); err != nil {
				mutex.Unlock()
				return err
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
