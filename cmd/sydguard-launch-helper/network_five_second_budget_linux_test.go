//go:build linux

package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

type networkDeadlineProbe struct{ seen chan time.Time }

func (a *networkDeadlineProbe) Create(ctx context.Context, _ networkPlan, _ string) (networkObject, error) {
	d, _ := ctx.Deadline()
	a.seen <- d
	return networkObject{}, errors.New("stop at first operation")
}
func (*networkDeadlineProbe) Activate(context.Context, networkPlan, []networkObject) error {
	return errors.New("unexpected activation")
}
func (*networkDeadlineProbe) RemoveIfIdentityMatches(context.Context, networkPlan, networkObject) error {
	return errors.New("unexpected cleanup")
}

func TestNetworkLifecycleFiveSecondBudgetStartsBeforeLock(t *testing.T) {
	for _, operation := range []string{"prepare", "prebind"} {
		t.Run(operation, func(t *testing.T) {
			_, base, _, slot, owner, j, _ := networkFixture(t)
			slot.lifecycleMu.Lock()
			seen := make(chan time.Time, 1)
			done := make(chan error, 1)
			start := time.Now()
			go func() {
				if operation == "prepare" {
					candidate := j
					done <- prepareNetwork(context.Background(), base, slot, owner, &candidate, &networkDeadlineProbe{seen})
				} else {
					_, err := prebindNetworkListenersWithBind(context.Background(), base, slot, owner, j, func(ctx context.Context, _ networkPlan) (*networkListeners, error) {
						d, _ := ctx.Deadline()
						seen <- d
						return nil, errors.New("stop before sockets")
					})
					done <- err
				}
			}()
			time.Sleep(300 * time.Millisecond)
			slot.lifecycleMu.Unlock()
			select {
			case deadline := <-seen:
				if elapsed := deadline.Sub(start); elapsed < 4900*time.Millisecond || elapsed > 5250*time.Millisecond {
					t.Fatalf("five-second deadline starts after lock: %v", elapsed)
				}
				if remaining := time.Until(deadline); remaining > 4900*time.Millisecond || remaining < 4*time.Second {
					t.Fatalf("lock wait missing from deadline: %v", remaining)
				}
			case <-time.After(time.Second):
				t.Fatal("operation did not acquire lock")
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("probe unexpectedly succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("operation did not return")
			}
		})
	}
}
