package controller

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func authorityFixture(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	path, err := os.MkdirTemp(home, ".sg-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(path) })
	return path
}

func TestConcurrentTokenPublication(t *testing.T) {
	directory := authorityFixture(t)
	if err := privateState(directory); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	results := make(chan string, 24)
	for i := 0; i < 24; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			token, err := operatorToken(directory)
			if err != nil {
				t.Error(err)
				return
			}
			results <- token
		}()
	}
	group.Wait()
	close(results)
	var expected string
	for token := range results {
		if expected == "" {
			expected = token
		}
		if token != expected {
			t.Fatal("concurrent callers got different operator authorities")
		}
	}
	if len(expected) != 64 {
		t.Fatal("no valid published token")
	}
}

func TestRejectTokenSymlink(t *testing.T) {
	directory := authorityFixture(t)
	if err := os.Symlink(filepath.Join(directory, "missing"), filepath.Join(directory, "operator.token")); err != nil {
		t.Fatal(err)
	}
	if _, err := operatorToken(directory); err == nil {
		t.Fatal("symlink token accepted")
	}
}

func TestUnixControllerLifecycle(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("controller lives in Linux")
	}
	directory := authorityFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, directory) }()
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
	client, err := OpenClient(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	deadline := time.Now().Add(5 * time.Second)
	for client.Health(ctx) != nil {
		if time.Now().After(deadline) {
			t.Fatal("controller never became healthy")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := Serve(ctx, directory); err == nil {
		t.Fatal("second controller acquired active endpoint")
	}
	registered, err := client.Register(ctx, "/projects/demo", "", []string{"pi", "private"})
	if err != nil {
		t.Fatal(err)
	}
	values, err := client.Sessions(ctx, false)
	if err != nil || len(values) != 1 || values[0].Name != "demo" {
		t.Fatalf("bad registered view: %+v %v", values, err)
	}
	if err := client.Complete(ctx, registered); err != nil {
		t.Fatal(err)
	}
	values, err = client.Sessions(ctx, false)
	if err != nil || len(values) != 0 {
		t.Fatalf("completion didn't release session: %+v %v", values, err)
	}
	values, err = client.Sessions(ctx, true)
	if err != nil || len(values) != 1 {
		t.Fatalf("history missing: %+v %v", values, err)
	}
}
