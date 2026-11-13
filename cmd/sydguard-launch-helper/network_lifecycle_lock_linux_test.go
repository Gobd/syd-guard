//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestNetworkLifecycleLockCancellationLeavesJournalAndSocketsUntouched(t *testing.T) {
	for _, operation := range []string{"prepare", "prebind", "native-prebind"} {
		for _, alreadyCanceled := range []bool{false, true} {
			t.Run(operation+map[bool]string{true: "-already-canceled", false: "-deadline"}[alreadyCanceled], func(t *testing.T) {
				base, baseFD, _, slot, owner, j, f := networkFixture(t)
				path := filepath.Join(base, journalName(slot))
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var binds atomic.Int32
				slot.lifecycleMu.Lock()
				locked := true
				defer func() {
					if locked {
						slot.lifecycleMu.Unlock()
					}
				}()
				ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancel()
				if alreadyCanceled {
					cancel()
				}
				done := make(chan error, 1)
				go func() {
					switch operation {
					case "prepare":
						candidate := j
						done <- prepareNetwork(ctx, baseFD, slot, owner, &candidate, f)
					case "prebind":
						_, err := prebindNetworkListenersWithBind(ctx, baseFD, slot, owner, j, func(context.Context, networkPlan) (*networkListeners, error) {
							binds.Add(1)
							return nil, errors.New("unexpected bind")
						})
						done <- err
					case "native-prebind":
						l, err := prebindNetworkListeners(ctx, baseFD, slot, owner, j)
						if l != nil {
							l.Close()
						}
						done <- err
					}
				}()
				select {
				case err := <-done:
					if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("wrong error: %v", err)
					}
				case <-time.After(2 * time.Second):
					slot.lifecycleMu.Unlock()
					locked = false
					<-done
					t.Fatal("did not return while lock remained held")
				}
				if slot.lifecycleMu.TryLock() {
					slot.lifecycleMu.Unlock()
					t.Fatal("operation released another owner's lock")
				}
				if binds.Load() != 0 || len(f.events) != 0 {
					t.Fatal("adapter or socket binder called while lock held")
				}
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatalf("journal changed: %v", err)
				}
				slot.lifecycleMu.Unlock()
				locked = false
				if !slot.lifecycleMu.TryLock() {
					t.Fatal("waiter retained lock after cancellation")
				}
				slot.lifecycleMu.Unlock()
			})
		}
	}
}

type networkBudgetAdapter struct {
	called chan time.Time
}

func (a *networkBudgetAdapter) Create(ctx context.Context, _ networkPlan, _ string) (networkObject, error) {
	d, _ := ctx.Deadline()
	a.called <- d
	<-ctx.Done()
	return networkObject{}, ctx.Err()
}
func (*networkBudgetAdapter) Activate(context.Context, networkPlan, []networkObject) error {
	return errors.New("unexpected activation")
}
func (*networkBudgetAdapter) RemoveIfIdentityMatches(context.Context, networkPlan, networkObject) error {
	return errors.New("unexpected removal")
}

func TestNetworkLifecycleLockWaitConsumesTransactionDeadline(t *testing.T) {
	for _, operation := range []string{"prepare", "prebind"} {
		t.Run(operation, func(t *testing.T) {
			_, baseFD, _, slot, owner, j, _ := networkFixture(t)
			slot.lifecycleMu.Lock()
			ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
			defer cancel()
			deadline, _ := ctx.Deadline()
			observed := make(chan time.Time, 1)
			done := make(chan error, 1)
			go func() {
				if operation == "prepare" {
					a := &networkBudgetAdapter{called: observed}
					candidate := j
					done <- prepareNetwork(ctx, baseFD, slot, owner, &candidate, a)
				} else {
					_, err := prebindNetworkListenersWithBind(ctx, baseFD, slot, owner, j, func(ctx context.Context, _ networkPlan) (*networkListeners, error) {
						d, _ := ctx.Deadline()
						observed <- d
						<-ctx.Done()
						return nil, ctx.Err()
					})
					done <- err
				}
			}()
			time.Sleep(180 * time.Millisecond)
			slot.lifecycleMu.Unlock()
			select {
			case d := <-observed:
				if !d.Equal(deadline) {
					t.Fatalf("fresh deadline after lock: got %s want %s", d, deadline)
				}
				if time.Until(d) > 300*time.Millisecond {
					t.Fatal("lock wait not charged to budget")
				}
			case <-time.After(time.Second):
				t.Fatal("operation did not acquire lock")
			}
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("error: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("operation exceeded original budget")
			}
		})
	}
}
