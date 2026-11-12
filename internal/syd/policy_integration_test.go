package syd

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestReadableProjectPolicyMutationDeniedIntegration(t *testing.T) {
	engine := os.Getenv("SYDGUARD_TEST_SYD")
	if runtime.GOOS != "linux" || engine == "" {
		t.Skip("requires Linux and explicit tested Syd")
	}
	work, temporary, authority := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.Chmod(authority, 0o700); err != nil { //nolint:gosec // private directory needs owner execute for profile traversal
		t.Fatal(err)
	}
	directory := filepath.Join(work, ".sydguard")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "default.json")
	if err := os.WriteFile(configPath, []byte("{\"version\":1}"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A preexisting hardlink tests the underlying inode, not just path denial.
	aliasPath := filepath.Join(work, "preexisting-alias.json")
	if err := os.Link(configPath, aliasPath); err != nil {
		t.Fatal(err)
	}
	profile, err := Profile(work, temporary, []string{authority})
	if err != nil {
		t.Fatal(err)
	}
	rules, err := ReadablePolicyRules(directory)
	if err != nil {
		t.Fatal(err)
	}
	profile += rules
	path := filepath.Join(authority, "policy.syd-3")
	if err := os.WriteFile(path, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	script := `set -eu
cat .sydguard/default.json
if printf replace > .sydguard/default.json; then exit 91; fi
if rm .sydguard/default.json; then exit 92; fi
if mv .sydguard renamed-policy; then exit 93; fi
if ln .sydguard/default.json alias.json; then exit 94; fi
if printf alias > preexisting-alias.json; then exit 95; fi
printf READABLE_POLICY_PROTECTED_PASS
`
	command := exec.CommandContext(ctx, engine, "-P", path, "--", "/bin/sh", "-c", script) //nolint:gosec // fixed adversarial payload and test-owned generated profile
	command.Dir = work
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("policy boundary failed: %v %s", err, output)
	}
	data, err := os.ReadFile(configPath) //nolint:gosec // test-owned profile in a temporary directory
	if err != nil || string(data) != "{\"version\":1}" {
		t.Fatalf("operator config changed: %v %q", err, data)
	}
}

// TestManagedPolicyMountOwnershipIntegration probes only disposable fixture
// inodes. Some shared mounts report root ownership but still permit writes.
func TestManagedPolicyMountOwnershipIntegration(t *testing.T) {
	root := os.Getenv("SYDGUARD_MANAGED_MOUNT_TEST_ROOT")
	if runtime.GOOS != "linux" || root == "" {
		t.Skip("requires Linux, sudo and an explicit disposable fixture parent")
	}
	work, err := os.MkdirTemp(root, ".sydguard-mount-test-")
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(work, ".sydguard")
	policy := filepath.Join(directory, "default.json")
	alias := filepath.Join(work, "alias.json")
	source := filepath.Join(work, "source")
	defer func() {
		for _, args := range [][]string{{"rm", "-f", "--", alias, policy}, {"rmdir", "--", directory}} {
			if output, err := exec.Command("sudo", append([]string{"-n"}, args...)...).CombinedOutput(); err != nil { //nolint:gosec // exact disposable fixture paths
				t.Errorf("fixture cleanup: %v %s", err, output)
			}
		}
		if err := os.Remove(source); err != nil && !os.IsNotExist(err) { //nolint:gosec // exact test-owned path under a disposable fixture
			t.Error(err)
		}
		if err := os.Remove(work); err != nil { //nolint:gosec // test-created disposable directory
			t.Error(err)
		}
	}()
	if err := os.WriteFile(source, []byte("reviewed"), 0o600); err != nil { //nolint:gosec // exact test-owned path under a disposable fixture
		t.Fatal(err)
	}
	for _, args := range [][]string{{"mkdir", "-m", "755", "--", directory}, {"install", "-m", "644", "--", source, policy}, {"ln", "--", policy, alias}} {
		if output, err := exec.Command("sudo", append([]string{"-n"}, args...)...).CombinedOutput(); err != nil { //nolint:gosec // exact disposable fixture paths
			t.Fatalf("fixture setup: %v %s", err, output)
		}
	}
	for _, path := range []string{directory, policy} {
		output, err := exec.Command("stat", "-c", "%u", "--", path).Output() //nolint:gosec // fixed command and exact disposable fixture path
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(string(output)) != "0" {
			t.Errorf("fixture is not root-owned: %s", path)
		}
	}
	for _, path := range []string{policy, alias} {
		if err := os.WriteFile(path, []byte("mutated"), 0o600); err == nil { //nolint:gosec // exact test-owned fixture paths
			t.Errorf("unprivileged write succeeded: %s", path)
		}
		if err := os.Chmod(path, 0o600); err == nil { //nolint:gosec // exact test-owned fixture paths
			t.Errorf("unprivileged chmod succeeded: %s", path)
		}
	}
	data, err := os.ReadFile(policy) //nolint:gosec // exact disposable fixture path
	if err != nil || string(data) != "reviewed" {
		t.Errorf("policy changed: %q: %v", data, err)
	}
}

// A read-only bind of the visible profile does not protect its backing inode
// from a different writable hardlink. This is a negative design fixture.
func TestReadOnlyPolicyBindDoesNotProtectHardlinkIntegration(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("SYDGUARD_NETNS_INTEGRATION") != "1" {
		t.Skip("requires disposable Linux mount namespace and sudo")
	}
	work := t.TempDir()
	profile := filepath.Join(work, "policy.json")
	alias := filepath.Join(work, "alias.json")
	if err := os.WriteFile(profile, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(profile, alias); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	script := `set -eu
mount --bind "$1" "$1"
mount -o remount,bind,ro "$1"
setpriv --reuid "$3" --regid "$4" --clear-groups --no-new-privs -- /bin/sh -c 'printf changed > "$1"' sh "$2"
`
	command := exec.CommandContext(ctx, "sudo", "-n", "unshare", "--mount", "--propagation", "private", "/bin/sh", "-c", script, "sh", profile, alias, strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid())) //nolint:gosec // fixed test-owned namespace, paths and script
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("mount namespace fixture: %v %s", err, output)
	}
	data, err := os.ReadFile(profile) //nolint:gosec // test-owned profile in a temporary directory
	if err != nil || string(data) != "changed" {
		t.Fatalf("expected backing inode mutation through alias, got %q: %v", data, err)
	}
}

// This test owns every path and does not adopt or change any checkout policy.
// Root owns only the fixture policy; the Syd process and workload stay unprivileged.
func TestRootOwnedPolicyHardlinkBoundaryIntegration(t *testing.T) {
	engine := os.Getenv("SYDGUARD_TEST_SYD")
	if runtime.GOOS != "linux" || engine == "" || os.Getenv("SYDGUARD_NETNS_INTEGRATION") != "1" {
		t.Skip("requires Linux, explicit tested Syd and sudo for test-owned policy")
	}
	if os.Getuid() == 0 {
		t.Fatal("fixture requires an unprivileged Syd process and workload")
	}
	work, temporary, authority := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.Chmod(authority, 0o700); err != nil { //nolint:gosec // private directory needs owner execute for profile traversal
		t.Fatal(err)
	}
	directory := filepath.Join(work, ".sydguard")
	if err := os.Mkdir(directory, 0o755); err != nil { //nolint:gosec // test verifies world-readable managed policy directory
		t.Fatal(err)
	}
	policy := filepath.Join(directory, "default.json")
	alias := filepath.Join(work, "alias.json")
	if err := os.WriteFile(policy, []byte("reviewed"), 0o644); err != nil { //nolint:gosec // intentionally readable test-owned profile
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	rootCommand := func(args ...string) {
		t.Helper()
		command := exec.CommandContext(ctx, "sudo", append([]string{"-n"}, args...)...) //nolint:gosec // fixed operations over fixture-owned temporary paths
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("fixture setup %v: %v %s", args, err, output)
		}
	}
	// Adopt a new, single-link inode only. A preexisting linked inode must not be chowned.
	rootCommand("chown", "0:0", "--", policy)
	rootCommand("chown", "0:0", "--", directory)
	defer func() {
		// These are the exact test-owned paths, not a recursive or arbitrary root API.
		if output, err := exec.Command("sudo", "-n", "rm", "-f", "--", policy).CombinedOutput(); err != nil { //nolint:gosec // exact test-owned file
			t.Errorf("cleanup policy: %v %s", err, output)
		}
		if output, err := exec.Command("sudo", "-n", "rmdir", "--", directory).CombinedOutput(); err != nil { //nolint:gosec // exact test-owned directory
			t.Errorf("cleanup policy directory: %v %s", err, output)
		}
	}()
	rootCommand("ln", "--", policy, alias)
	profile, err := Profile(work, temporary, []string{authority})
	if err != nil {
		t.Fatal(err)
	}
	rules, err := ReadablePolicyRules(directory)
	if err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(authority, "policy.syd-3")
	if err := os.WriteFile(profilePath, []byte(profile+rules), 0o600); err != nil {
		t.Fatal(err)
	}
	script := `set -eu
cat .sydguard/default.json
if printf mutated > alias.json; then exit 91; fi
if chmod 600 alias.json; then exit 92; fi
if rm .sydguard/default.json; then exit 93; fi
if mv .sydguard renamed-policy; then exit 94; fi
printf ROOT_OWNED_ALIAS_DENIED
`
	command := exec.CommandContext(ctx, engine, "-P", profilePath, "--", "/bin/sh", "-c", script) //nolint:gosec // fixed test-owned adversarial payload and generated profile
	command.Dir = work
	if output, err := command.CombinedOutput(); err != nil || !strings.Contains(string(output), "ROOT_OWNED_ALIAS_DENIED") {
		t.Fatalf("root-owned policy fixture: %v %s", err, output)
	}
	data, err := os.ReadFile(policy) //nolint:gosec // exact test-owned readable profile
	if err != nil || string(data) != "reviewed" {
		t.Fatalf("test profile changed: %v %q", err, data)
	}
}
