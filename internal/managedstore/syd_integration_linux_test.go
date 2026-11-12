//go:build linux

package managedstore

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/syd"
)

// This fixture tests a proposed caller-supplied protected-path preset, not an
// automatic guarantee of the current controller or arbitrary inherited FDs.
func TestSydManagedAuthorityIsolation(t *testing.T) {
	engine := os.Getenv("SYDGUARD_TEST_SYD")
	if engine == "" || os.Getenv("SYDGUARD_HELPER_TEST") != "1" {
		t.Skip("requires explicit Syd and disposable guest helper")
	}
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		t.Fatal("workload must run as an ordinary UID")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil { //nolint:gosec // private directory needs owner search permission
		t.Fatal(err)
	} // private Syd profile parent
	project := filepath.Join(parent, "project")
	temporary := filepath.Join(parent, "temporary")
	policy := filepath.Join(project, ".sydguard")
	for _, dir := range []string{project, temporary, policy} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	credential := filepath.Join(project, "credential-token")
	source := filepath.Join(project, "policy-source")
	for _, path := range []string{credential, source} {
		if err := os.WriteFile(path, []byte("fixture-secret"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(helperPath); err != nil {
		t.Fatalf("dedicated helper missing: %v", err)
	}
	// Open before exec: Go's CLOEXEC and the absence of ExtraFiles must keep this
	// exact credential inode out of the ordinary workload's descriptor table.
	secret, err := os.Open(credential) //nolint:gosec // test-owned fixture credential
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = secret.Close() }()
	// A deliberate inherited-FD control proves the shell probe can detect one.
	control := exec.Command("/bin/sh", "-c", `(eval ": <&3")`)
	control.ExtraFiles = []*os.File{secret}
	if err := control.Run(); err != nil {
		t.Fatalf("inherited FD control failed: %v", err)
	}
	if secret.Fd() < 3 || secret.Fd() > 9 {
		t.Fatalf("fixture requires shell-checkable credential FD, got %d", secret.Fd())
	}
	protected := []string{credential, source, helperPath, "/usr/bin/sudo"}
	profile, err := syd.Profile(project, temporary, protected)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range protected {
		if !strings.Contains(profile, "deny/all+"+value+"\n") {
			t.Fatalf("missing protected rule for %s", value)
		}
	}
	// Permit renames within the disposable parent so the test exercises the
	// explicit project and policy denies, not merely the baseline outside ceiling.
	profile += "allow/rename+" + parent + "/***\nallow/lock/rename+" + parent + "\n"
	profilePath := filepath.Join(parent, "fixture.syd-3")
	if err := os.WriteFile(profilePath, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	script := `set -eu
printf allowed > allowed
if cat "$1" >credential-result 2>&1; then echo CREDENTIAL_BYPASS; exit 41; fi
if cat "$2" >source-result 2>&1; then echo SOURCE_BYPASS; exit 42; fi
set +e
"$3" </dev/null >helper-result 2>&1
rc=$?
set -e
if [ "$rc" -ne 126 ]; then echo "HELPER_NOT_DENIED:$rc"; exit 43; fi
set +e
/usr/bin/sudo -n "$3" </dev/null >helper-result 2>&1
rc=$?
set -e
if [ "$rc" -ne 126 ]; then echo "SUDO_NOT_DENIED:$rc"; exit 44; fi
if mv "$4/.sydguard" "$4/policy-moved" >policy-rename-result 2>&1; then echo POLICY_RENAME_BYPASS; exit 45; fi
if mv "$4" "$4-moved" >parent-rename-result 2>&1; then echo PARENT_RENAME_BYPASS; exit 46; fi
if (eval ": <&$5") >fd-result 2>&1; then echo CREDENTIAL_FD_INHERITED; exit 47; fi
echo MANAGED_AUTHORITY_PASS
`
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, engine, "-P", profilePath, "--", "/bin/sh", "-c", script, "fixture", credential, source, helperPath, project, strconv.Itoa(int(secret.Fd()))) //nolint:gosec // explicit test engine and fixed fixture, paths are argv
	cmd.Dir = project
	cmd.Env = []string{"PATH=/usr/bin:/bin", "TMPDIR=" + temporary}
	output, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "MANAGED_AUTHORITY_PASS") {
		t.Fatalf("managed authority fixture: %v\n%s\nprofile:\n%s", err, output, profile)
	}
	if _, err := os.Stat(policy); err != nil {
		t.Fatalf("policy entry changed: %v", err)
	}
	if _, err := os.Stat(project); err != nil {
		t.Fatalf("project entry changed: %v", err)
	}
}
