//go:build linux

package managedstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// Requires a disposable Linux guest and separately installed, root-owned helper.
// See MANAGED_POLICY_HELPER.md; never run this through sudo.
func TestInstalledHelperIntegration(t *testing.T) {
	if os.Getenv("SYDGUARD_HELPER_TEST") != "1" {
		t.Skip("requires disposable guest setup")
	}
	if os.Getuid() == 0 {
		t.Fatal("test must run as a regular user")
	}
	dir, err := os.MkdirTemp("", "sydguard-policy-integration-")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("administrator must remove test directory: %s", dir)
	private := filepath.Join(dir, "private")
	project := filepath.Join(dir, "project")
	for _, path := range []string{private, project} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	credential := filepath.Join(private, "credential")
	if err := CreateCredential(credential); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(private, "hardlink")
	if err := os.Link(credential, alias); err != nil {
		t.Fatal(err)
	}
	invalid := exec.Command("/usr/bin/sudo", "-n", "/usr/local/libexec/sydguard-policy-admin", strconv.Itoa(os.Getuid()), alias) //nolint:gosec // test-owned path passed only to dedicated helper
	if err := invalid.Run(); err == nil {
		t.Fatal("enrolled a credential with multiple links")
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(credential, alias); err != nil {
		t.Fatal(err)
	}
	invalid = exec.Command("/usr/bin/sudo", "-n", "/usr/local/libexec/sydguard-policy-admin", strconv.Itoa(os.Getuid()), alias) //nolint:gosec // test-owned path passed only to dedicated helper
	if err := invalid.Run(); err == nil {
		t.Fatal("enrolled symlink credential")
	}
	wrongUID := exec.Command("/usr/bin/sudo", "-n", "/usr/local/libexec/sydguard-policy-admin", strconv.Itoa(os.Getuid()+1), credential) //nolint:gosec // test-owned credential and dedicated helper
	if err := wrongUID.Run(); err == nil {
		t.Fatal("accepted wrong credential owner UID")
	}
	cmd := exec.Command("/usr/bin/sudo", "-n", "/usr/local/libexec/sydguard-policy-admin", strconv.Itoa(os.Getuid()), credential) //nolint:gosec // test-owned path passed only to dedicated helper
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("enroll: %v: %s", err, output)
	}
	forbidden := exec.Command("/usr/bin/sudo", "-n", helperPath, "--enroll", strconv.Itoa(os.Getuid()), credential) //nolint:gosec // dedicated test helper
	if err := forbidden.Run(); err == nil {
		t.Fatal("RPC helper accepted enrollment arguments")
	}
	secret, err := os.ReadFile(credential) //nolint:gosec // exclusively created test credential
	if err != nil {
		t.Fatal(err)
	}
	probe, err := json.Marshal(Request{Operation: "read", Project: "invalid", Name: "test", Credential: string(secret)})
	if err != nil {
		t.Fatal(err)
	}
	probeCmd := exec.Command("/usr/bin/sudo", "-n", helperPath)
	probeCmd.Stdin = bytes.NewReader(probe)
	output, _ := probeCmd.Output()
	if bytes.Contains(output, secret) {
		t.Fatal("helper returned credential")
	}
	client, err := NewClient(credential)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	id, err := client.Register(ctx, project)
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 64 || id == project {
		t.Fatal("registration ID not opaque")
	}
	if _, err := client.Register(ctx, project); err == nil {
		t.Fatal("adopted preexisting managed directory")
	}
	created, err := client.Create(ctx, id, "test")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(project, ".sydguard", "test.json")
	if err := os.WriteFile(file, []byte("attacker"), 0o600); err == nil {
		t.Fatal("normal UID wrote root policy")
	}
	if err := os.Chmod(file, 0o600); err == nil {
		t.Fatal("normal UID chmod root policy")
	}
	next := json.RawMessage(`{ "version":1,"name":"test","files":[{"path":"src","access":["read","write"],"recursive":true}],"network":[{"host":"example.com","port":443,"transport":"tcp"}]}`)
	changed, err := client.Replace(ctx, id, "test", created.Revision, next)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Revision == created.Revision {
		t.Fatal("replacement did not change revision")
	}
	bad := json.RawMessage(`{"version":1,"name":"test","files":[],"network":[],"unexpected":1}`)
	_, err = client.Replace(ctx, id, "test", "stale", bad)
	var apiErr *ClientError
	if !errors.As(err, &apiErr) || apiErr.Code != "409" {
		t.Fatalf("stale revision: %v", err)
	}
	for _, invalid := range []string{
		`{"version":1,"name":"test","files":[{"path":"src","capabilities":["read"],"recursive":true}],"network":[]}`,
		`{"version":1,"name":"test","files":[{"path":"src","access":["execute"],"recursive":true}],"network":[]}`,
		`{"version":1,"name":"test","files":[{"path":"/","access":["read"],"recursive":true}],"network":[]}`,
		`{"version":1,"name":"test","files":[],"files":[],"network":[]}`,
		`{"version":1,"name":"test","files":[],"network":[],"unexpected":1}`,
	} {
		if _, err := client.Replace(ctx, id, "test", changed.Revision, json.RawMessage(invalid)); err == nil {
			t.Fatalf("accepted invalid current-revision payload: %s", invalid)
		}
	}
	read, err := client.Read(ctx, id, "test")
	if err != nil || read.Revision != changed.Revision || !bytes.Equal(read.Profile, next) {
		t.Fatalf("read after conflict: %v", err)
	}
	other := filepath.Join(private, "other")
	if err := CreateCredential(other); err != nil {
		t.Fatal(err)
	}
	wrong, err := NewClient(other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Read(ctx, id, "test"); err == nil {
		t.Fatal("accepted wrong credential")
	}
	// Two simultaneous writers with the same revision must not both commit.
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, err := client.Replace(ctx, id, "test", changed.Revision, json.RawMessage(`{"name":"test","version":1,"files":[],"network":[]}`))
			results <- err
		}()
	}
	first, second := <-results, <-results
	if (first == nil) == (second == nil) {
		t.Fatalf("concurrent replacements: %v; %v", first, second)
	}
	collision := filepath.Join(dir, "collision")
	if err := os.Mkdir(collision, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(collision, ".sydguard"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(collision, ".sydguard", "sentinel"), []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Register(ctx, collision); err == nil {
		t.Fatal("adopted existing user folder")
	}
	if b, err := os.ReadFile(filepath.Join(collision, ".sydguard", "sentinel")); err != nil || string(b) != "unchanged" { //nolint:gosec // test-owned path
		t.Fatal("existing folder changed")
	}
	for i := 0; i < 10; i++ {
		candidate := filepath.Join(dir, "race-"+strconv.Itoa(i))
		if err := os.Mkdir(candidate, 0o700); err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		start := make(chan struct{})
		go func() { <-start; _, err := client.Register(ctx, candidate); result <- err }()
		close(start)
		mkdirErr := os.Mkdir(filepath.Join(candidate, ".sydguard"), 0o700)
		registerErr := <-result
		if (mkdirErr == nil) == (registerErr == nil) {
			t.Fatalf("race must have exactly one winner: mkdir=%v register=%v", mkdirErr, registerErr)
		}
		if mkdirErr == nil {
			info, err := os.Stat(filepath.Join(candidate, ".sydguard"))
			if err != nil || info.Mode().Perm() != 0o700 {
				t.Fatal("raced preexisting directory changed")
			}
		}
	}
	shared, err := os.MkdirTemp("/dev/shm", "sydguard-cross-fs-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(shared) }()
	if _, err := client.Register(ctx, shared); !errors.As(err, &apiErr) || apiErr.Code != "unsupported_filesystem" {
		t.Fatalf("cross-filesystem registration: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(shared, ".sydguard")); !os.IsNotExist(err) {
		t.Fatal("cross-filesystem registration touched project")
	}
	if err := os.Rename(filepath.Join(project, ".sydguard"), filepath.Join(project, "old")); err != nil {
		t.Fatal(err)
	}
	// Consumers retain and use the exact authenticated bytes, not a reopened path.
	if !bytes.Equal(read.Profile, next) || read.Revision != changed.Revision {
		t.Fatal("returned snapshot changed after namespace rename")
	}
	if err := os.Symlink("old", filepath.Join(project, ".sydguard")); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(ctx, id, "test"); err == nil {
		t.Fatal("followed symlink policy directory")
	}
	if err := os.Remove(filepath.Join(project, ".sydguard")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(project, "old"), filepath.Join(project, ".sydguard")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(project, project+"-moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(ctx, id, "test"); err == nil {
		t.Fatal("accepted replaced project ancestor")
	}
	if _, err := client.Register(ctx, "/proc/self"); err == nil {
		t.Fatal("registered proc path")
	}
}

// The installed root helper, not a root-run Go test binary, must bound an open
// stdin even if the caller never provides a request or closes its pipe.
func TestInstalledHelperStalledInput(t *testing.T) {
	if os.Getenv("SYDGUARD_HELPER_TEST") != "1" {
		t.Skip("requires disposable guest setup")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 26*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/sudo", "-n", helperPath)
	pipe, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pipe.Close() }()
	cmd.WaitDelay = 2 * time.Second
	start := time.Now()
	if err := cmd.Run(); err == nil || ctx.Err() != nil {
		t.Fatalf("stalled input: err=%v context=%v", err, ctx.Err())
	}
	if elapsed := time.Since(start); elapsed < 18*time.Second || elapsed > 25*time.Second {
		t.Fatalf("helper deadline elapsed %v", elapsed)
	}
}

func TestInstalledHelperCancellationPipes(t *testing.T) {
	if os.Getenv("SYDGUARD_HELPER_TEST") != "1" {
		t.Skip("requires disposable guest setup")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/sudo", "-n", helperPath)
	pipe, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pipe.Close() }()
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.WaitDelay = 2 * time.Second
	start := time.Now()
	if err := cmd.Run(); err == nil || ctx.Err() == nil {
		t.Fatalf("expected cancellation: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("pipe wait not bounded: %v", elapsed)
	}
}
