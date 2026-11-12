//go:build linux

package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/network"
	"github.com/Gobd/syd-guard/internal/syd"
)

func TestTransparentControllerNamespaceIntegration(t *testing.T) {
	if os.Getenv("SYDGUARD_CONTROLLER_NETNS_INTEGRATION") != "1" {
		t.Skip("explicit disposable Linux namespace integration")
	}
	state := authorityFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, state) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	client, err := OpenClient(state)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	deadline := time.Now().Add(5 * time.Second)
	for client.Health(ctx) != nil {
		if time.Now().After(deadline) {
			t.Fatal("controller unavailable")
		}
		time.Sleep(20 * time.Millisecond)
	}
	value, err := client.RegisterTransparent(ctx, "/tmp/fixture", "", []string{"fixture"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Complete(ctx, value) }()
	if !strings.HasPrefix(value.Namespace, "sg-") || value.TransitDNS == "" {
		t.Fatalf("bad contract %+v", value)
	}
	list, err := client.Sessions(ctx, false)
	if err != nil || len(list) != 1 || list[0].Namespace != value.Namespace || list[0].TransitDNS != value.TransitDNS {
		t.Fatalf("session metadata: %+v %v", list, err)
	}
	probeCtx, stop := context.WithTimeout(ctx, 10*time.Second)
	defer stop()
	args := []string{"-n", "--", "/usr/sbin/ip", "netns", "exec", value.Namespace, "setpriv", "--reuid", strconv.Itoa(os.Getuid()), "--regid", strconv.Itoa(os.Getgid()), "--clear-groups", "--no-new-privs", "--bounding-set=-all", "--", "/usr/bin/getent", "ahostsv4", "fixture.example.com"}
	out, err := exec.CommandContext(probeCtx, "/usr/bin/sudo", args...).CombinedOutput() //nolint:gosec // fixed probe and controller-created namespace, unprivileged child
	if err != nil || !strings.Contains(string(out), "198.18.") {
		t.Fatalf("namespace DNS: %v %s", err, out)
	}
	pending, err := client.Operate(ctx, "GET", "/api/network/pending", nil)
	if err != nil || string(pending) != "[]" {
		t.Fatalf("DNS created pending: %s %v", pending, err)
	}
	if engine := os.Getenv("SYDGUARD_TEST_SYD"); engine != "" {
		run := filepath.Join(state, "runs", "run-integration")
		if err = os.MkdirAll(run, 0o700); err != nil {
			t.Fatal(err)
		}
		work, temporary := t.TempDir(), t.TempDir()
		profile, err := syd.Profile(work, temporary, []string{run})
		if err != nil {
			t.Fatal(err)
		}
		socket := filepath.Join(run, "syd.sock")
		profile += fmt.Sprintf("allow/lock/connect+1-65535\nipc:%s\nlock:ipc\n", socket)
		profilePath := filepath.Join(run, "profile.syd-3")
		if err = os.WriteFile(profilePath, []byte(profile), 0o600); err != nil {
			t.Fatal(err)
		}
		sydCtx, stopSyd := context.WithCancel(ctx)
		defer stopSyd()
		process := exec.CommandContext(sydCtx, engine, "-P", profilePath, "--", "/bin/sleep", "30") //nolint:gosec // explicit test engine and generated private profile
		process.Dir = work
		if err = process.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = process.Process.Kill(); _ = process.Wait() }()
		end := time.Now().Add(5 * time.Second)
		for {
			if info, e := os.Lstat(socket); e == nil && info.Mode()&os.ModeSocket != 0 {
				break
			}
			if time.Now().After(end) {
				t.Fatal("Syd IPC did not start")
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err = client.NetworkReady(ctx, value.ID, socket); err != nil {
			t.Fatalf("real Syd network ready: %v", err)
		}
		ip := strings.Fields(string(out))[0]
		if err = client.NetworkEvent(ctx, value.ID, NetworkEvent{Endpoint: ip + ":8443"}); err != nil {
			t.Fatalf("event: %v", err)
		}
		raw, err := client.Operate(ctx, "GET", "/api/network/pending", nil)
		if err != nil {
			t.Fatal(err)
		}
		var pending []network.Pending
		if err = json.Unmarshal(raw, &pending); err != nil || len(pending) != 1 {
			t.Fatalf("pending %s: %v", raw, err)
		}
		if _, err = client.Operate(ctx, "POST", "/api/network/decisions", network.Decision{ID: pending[0].ID, Action: "allow", Scope: "run"}); err != nil {
			t.Fatalf("real Syd grant: %v", err)
		}
	}
	if err = client.Complete(ctx, value); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat("/run/netns/" + value.Namespace); !os.IsNotExist(err) {
		t.Fatalf("namespace still exists: %v", err)
	}
}
