//go:build linux

package netns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRuntimePrefixInventory(t *testing.T) {
	topology, err := New()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		routes string
		fail   bool
	}{
		{`[{"dst":"default"},{"dst":"192.0.2.0/24"}]`, false},
		{fmt.Sprintf(`[{"dst":%q}]`, topology.Host.String()), true},
		{`[{"dst":"10.232.0.0/16"}]`, true},
		{`[{"dst":"not-a-route"}]`, true},
		{`not-json`, true},
	} {
		run := func(_ context.Context, cmd Command) ([]byte, error) {
			if cmd.Args[2] == "address" {
				return []byte(`[]`), nil
			}
			return []byte(tc.routes), nil
		}
		if (checkPrefix(context.Background(), run, topology.Prefix) != nil) != tc.fail {
			t.Fatalf("unexpected result for %s", tc.routes)
		}
	}
}

func TestRuntimePrefixAddressInventory(t *testing.T) {
	topology, err := New()
	if err != nil {
		t.Fatal(err)
	}
	run := func(_ context.Context, cmd Command) ([]byte, error) {
		if cmd.Args[2] == "address" {
			return []byte(fmt.Sprintf(`[{"addr_info":[{"local":%q,"prefixlen":30}]}]`, topology.Host.String())), nil
		}
		return []byte(`[]`), nil
	}
	if err := checkPrefix(context.Background(), run, topology.Prefix); err == nil {
		t.Fatal("accepted overlapping address without a route")
	}
}

func privateTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // private directory must be searchable
		t.Fatal(err)
	}
	return dir
}

func TestRuntimePrivateStateAndLock(t *testing.T) {
	dir := privateTestDir(t)
	if _, err := validateStateDir(dir); err != nil {
		t.Fatal(err)
	}
	first, err := lockState(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := lockState(ctx, dir); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second lock: %v", err)
	}
	unlockState(first)
	if err := os.Remove(filepath.Join(dir, ".netns.lock")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", filepath.Join(dir, ".netns.lock")); err != nil {
		t.Fatal(err)
	}
	if _, err := lockState(context.Background(), dir); err == nil {
		t.Fatal("accepted symlink lock")
	}
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // verify rejection of an intentionally nonprivate test directory
		t.Fatal(err)
	}
	if _, err := validateStateDir(dir); err == nil {
		t.Fatal("accepted nonprivate state directory")
	}
}

func integrationRuntime(t *testing.T) {
	t.Helper()
	if os.Getenv("SYDGUARD_NETNS_INTEGRATION") != "1" {
		t.Skip("explicit disposable Linux namespace test requires sudo")
	}
}

func TestRuntimeCreateResolverAndCleanupIntegration(t *testing.T) {
	integrationRuntime(t)
	dns, err := net.Listen("tcp4", "0.0.0.0:0") //nolint:gosec // opt-in isolated network fixture tests transit-address listener
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dns.Close() }()
	tcp, err := net.Listen("tcp4", "0.0.0.0:0") //nolint:gosec // opt-in isolated network fixture tests transit-address listener
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tcp.Close() }()
	dnsPort, _ := portOf(dns)
	tcpPort, _ := portOf(tcp)
	topology, err := New()
	if err != nil {
		t.Fatal(err)
	}
	dir := privateTestDir(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r, err := Create(ctx, topology, dnsPort, tcpPort, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	}()
	cmd, err := r.UserExec(os.Getuid(), os.Getgid(), []string{"/bin/cat", "/etc/resolv.conf"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := runCommand(ctx, cmd)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := r.UserExec(os.Getuid(), os.Getgid(), []string{"/usr/bin/id", "-u"})
	if err != nil {
		t.Fatal(err)
	}
	identityOut, err := runCommand(ctx, identity)
	if err != nil || strings.TrimSpace(string(identityOut)) != fmt.Sprint(os.Getuid()) {
		t.Fatalf("workload uid: %q %v", identityOut, err)
	}
	want := fmt.Sprintf("nameserver %s\noptions attempts:1 timeout:1\n", topology.Host)
	if string(out) != want {
		t.Fatalf("resolver %q; want %q", out, want)
	}
	other, err := New()
	if err != nil {
		t.Fatal(err)
	}
	other.Host, other.Agent, other.Prefix = topology.Host, topology.Agent, topology.Prefix
	if _, err := Create(ctx, other, dnsPort, tcpPort, dir); err == nil {
		t.Fatal("accepted overlapping transit prefix")
	}
	if err := dns.Close(); err != nil {
		t.Fatal(err)
	}
	cmd, err = r.UserExec(os.Getuid(), os.Getgid(), []string{"/usr/bin/curl", "--noproxy", "*", "--max-time", "1", "http://" + topology.Host.String() + ":53"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runCommand(ctx, cmd); err == nil {
		t.Fatal("connection succeeded after listener closed")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if _, err := os.Lstat(filepath.Join("/etc/netns", topology.Namespace)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("resolver directory remains: %v", err)
	}
	if _, err := net.InterfaceByName(topology.HostLink); err == nil {
		t.Fatal("link remains")
	}
	if _, err := tableIdentity(ctx, runCommand, topology.Table); err == nil {
		t.Fatal("nft table remains")
	}
	if _, err := namespaceIdentity(topology.Namespace); err == nil {
		t.Fatal("namespace remains")
	}
}

func TestRuntimeRollbackIntegration(t *testing.T) {
	integrationRuntime(t)
	for fail := 0; fail < 15; fail++ {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			topology, err := New()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			count := 0
			run := func(ctx context.Context, cmd Command) ([]byte, error) {
				// Fail only setup mutations, never inventories or rollback commands.
				setup := cmd.Program == "install" || cmd.Program == "mkdir" && strings.HasSuffix(cmd.Args[len(cmd.Args)-1], topology.Namespace) || cmd.Program == "ip" && !strings.Contains(strings.Join(cmd.Args, " "), " del ") && len(cmd.Args) > 0 && cmd.Args[0] != "-j" || cmd.Program == "nft" && len(cmd.Args) > 0 && cmd.Args[0] == "-f"
				if setup {
					if count == fail {
						count++
						return nil, errors.New("injected failure")
					}
					count++
				}
				return runCommand(ctx, cmd)
			}
			r, err := create(ctx, topology, 53001, 53002, privateTestDir(t), run)
			if r != nil {
				if err := r.Close(); err != nil {
					t.Fatal(err)
				}
				if fail < count {
					t.Fatal("expected injected failure")
				}
				return
			}
			if err == nil {
				t.Fatal("missing error")
			}
			if _, err := os.Lstat(filepath.Join("/etc/netns", topology.Namespace)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("resolver remains: %v", err)
			}
			if _, err := net.InterfaceByName(topology.HostLink); err == nil {
				t.Fatal("link remains")
			}
			if _, err := namespaceIdentity(topology.Namespace); err == nil {
				t.Fatal("namespace remains")
			}
			if _, err := tableIdentity(ctx, runCommand, topology.Table); err == nil {
				t.Fatal("table remains")
			}
		})
	}
}

func TestRuntimeTableCollisionIntegration(t *testing.T) {
	integrationRuntime(t)
	topology, err := New()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := runCommand(ctx, Command{Program: "nft", Args: []string{"create", "table", "inet", topology.Table}}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = exec.Command("/usr/bin/sudo", "-n", "/usr/sbin/nft", "delete", "table", "inet", topology.Table).Run() //nolint:gosec // deletes only the test-created randomly named table
	}()
	before, err := tableIdentity(ctx, runCommand, topology.Table)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Create(ctx, topology, 53001, 53002, privateTestDir(t)); err == nil {
		t.Fatal("accepted colliding table")
	}
	after, err := tableIdentity(ctx, runCommand, topology.Table)
	if err != nil || after != before {
		t.Fatalf("colliding table changed: %d %v", after, err)
	}
}

func TestRuntimeConcurrentPrefixCollisionIntegration(t *testing.T) {
	integrationRuntime(t)
	a, err := New()
	if err != nil {
		t.Fatal(err)
	}
	b, err := New()
	if err != nil {
		t.Fatal(err)
	}
	b.Host, b.Agent, b.Prefix = a.Host, a.Agent, a.Prefix
	dir := privateTestDir(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	type result struct {
		r   *Runtime
		err error
	}
	results := make(chan result, 2)
	for _, topology := range []Topology{a, b} {
		go func(topo Topology) { r, err := Create(ctx, topo, 53001, 53002, dir); results <- result{r, err} }(topology)
	}
	one, two := <-results, <-results
	if one.r != nil {
		defer func() {
			if err := one.r.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	if two.r != nil {
		defer func() {
			if err := two.r.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	if (one.err == nil) == (two.err == nil) {
		t.Fatalf("expected exactly one allocation: %v / %v", one.err, two.err)
	}
}

func TestRuntimeNamespaceCollisionIntegration(t *testing.T) {
	integrationRuntime(t)
	topology, err := New()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := runCommand(ctx, Command{Program: "ip", Args: []string{"netns", "add", topology.Namespace}}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = runCommand(context.Background(), Command{Program: "ip", Args: []string{"netns", "del", topology.Namespace}})
	}()
	before, err := namespaceIdentity(topology.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Create(ctx, topology, 53001, 53002, privateTestDir(t)); err == nil {
		t.Fatal("accepted colliding namespace")
	}
	after, err := namespaceIdentity(topology.Namespace)
	if err != nil || after != before {
		t.Fatalf("colliding namespace changed: %d %v", after, err)
	}
}

func TestRuntimeReplacedLinkIntegration(t *testing.T) {
	integrationRuntime(t)
	topology, err := New()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	r, err := Create(ctx, topology, 53001, 53002, privateTestDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runCommand(ctx, Command{Program: "ip", Args: []string{"link", "del", topology.HostLink}}); err != nil {
		t.Fatal(err)
	}
	if _, err := runCommand(ctx, Command{Program: "ip", Args: []string{"link", "add", topology.HostLink, "type", "dummy"}}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = runCommand(context.Background(), Command{Program: "ip", Args: []string{"link", "del", topology.HostLink}})
		_, _ = runCommand(context.Background(), Command{Program: "nft", Args: []string{"delete", "table", "inet", topology.Table}})
	}()
	replacement, err := linkIdentity(topology.HostLink)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err == nil {
		t.Fatal("expected replaced link error")
	}
	after, err := linkIdentity(topology.HostLink)
	if err != nil || after != replacement {
		t.Fatalf("replacement changed: %d %v", after, err)
	}
	if _, err := tableIdentity(ctx, runCommand, topology.Table); err != nil {
		t.Fatalf("firewall removed with replacement link: %v", err)
	}
}
