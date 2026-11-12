package controller

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestServeManagedCatalogFailureDoesNotPublish(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("controller requires Linux")
	}
	dir := authorityFixture(t)
	fixture := newCatalogFixture(t)
	fixture.catalogError = errors.New("authentication failed")
	err := ServeManaged(context.Background(), dir, func(ctx context.Context) (ProfileProvider, error) {
		return NewCatalogProfileProvider(ctx, fixture, true)
	})
	if err == nil || fixture.catalogs != 1 {
		t.Fatal("failed catalog did not reject startup")
	}
	if _, err := os.Lstat(filepath.Join(dir, "controller.sock")); !os.IsNotExist(err) {
		t.Fatalf("endpoint published on failure: %v", err)
	}
}

func TestServeManagedCannotAlterActiveController(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("controller requires Linux")
	}
	dir := authorityFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, dir) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("controller failed to stop")
		}
	}()
	client, err := OpenClient(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	deadline := time.Now().Add(5 * time.Second)
	for client.Health(ctx) != nil {
		if time.Now().After(deadline) {
			t.Fatal("controller never started")
		}
		time.Sleep(20 * time.Millisecond)
	}
	invoked := false
	err = ServeManaged(ctx, dir, func(context.Context) (ProfileProvider, error) { invoked = true; return nil, errors.New("unexpected") })
	if err == nil || invoked {
		t.Fatal("managed startup changed or consulted active controller")
	}
	if err = client.Health(ctx); err != nil {
		t.Fatalf("active controller interrupted: %v", err)
	}
}

func TestServeManagedPublishesAuthenticatedProvider(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("controller requires Linux")
	}
	for _, edit := range []bool{false, true} {
		t.Run(map[bool]string{false: "read-only", true: "edit"}[edit], func(t *testing.T) {
			dir := authorityFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			fixture := newCatalogFixture(t)
			go func() {
				done <- ServeManaged(ctx, dir, func(ctx context.Context) (ProfileProvider, error) {
					return NewCatalogProfileProvider(ctx, fixture, edit)
				})
			}()
			defer func() {
				cancel()
				select {
				case err := <-done:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(5 * time.Second):
					t.Error("controller failed to stop")
				}
			}()
			client, err := OpenClient(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			deadline := time.Now().Add(5 * time.Second)
			for client.Health(ctx) != nil {
				if time.Now().After(deadline) {
					t.Fatal("controller never started")
				}
				time.Sleep(20 * time.Millisecond)
			}
			raw, err := client.Operate(ctx, "GET", "/api/profiles", nil)
			if err != nil {
				t.Fatal(err)
			}
			var records []ProfileRecord
			if err := json.Unmarshal(raw, &records); err != nil {
				t.Fatal(err)
			}
			if len(records) != 1 || records[0].Capabilities.Edit != edit || records[0].Capabilities.Reload || records[0].Capabilities.SavedDecisions {
				t.Fatalf("unexpected capability: %s", raw)
			}
		})
	}
}
