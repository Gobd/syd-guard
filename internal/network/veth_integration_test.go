package network

import (
	"context"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/netns"
)

func TestVethHostnamePortApprovalIntegration(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("SYDGUARD_NETNS_INTEGRATION") != "1" {
		t.Skip("explicit Linux veth test requires sudo and public HTTPS fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	topology, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	mapping := NewSynthetic()
	address, err := mapping.Address("example.com")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewPolicy("")
	if err != nil {
		t.Fatal(err)
	}
	dns, err := StartDNS(mapping, topology.Agent)
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	gate, err := StartTransparent(mapping, policy, "veth-test", "fixture", topology.Agent)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	port := func(endpoint string) uint16 {
		_, text, err := net.SplitHostPort(endpoint)
		if err != nil {
			t.Fatal(err)
		}
		value, err := strconv.ParseUint(text, 10, 16)
		if err != nil {
			t.Fatal(err)
		}
		return uint16(value)
	}
	commands, err := topology.Prepare(port(dns.Address), port(gate.Address))
	if err != nil {
		t.Fatal(err)
	}
	cleanup, err := topology.Cleanup()
	if err != nil {
		t.Fatal(err)
	}
	created := [3]bool{} // namespace, veth, nft table; only remove successfully created resources
	defer func() {
		for i, command := range cleanup {
			if !created[2-i] {
				continue
			}
			argv := append([]string{"-n", command.Program}, command.Args...)
			_ = exec.Command("sudo", argv...).Run() //nolint:gosec // generated test-owned cleanup; context may already be canceled
		}
	}()
	run := func(command netns.Command) ([]byte, error) {
		argv := append([]string{"-n", command.Program}, command.Args...)
		process := exec.CommandContext(ctx, "sudo", argv...) //nolint:gosec // generated namespace test commands, explicit integration opt-in
		process.Stdin = strings.NewReader(command.Input)
		return process.CombinedOutput()
	}
	for i, command := range commands {
		output, err := run(command)
		if err != nil {
			t.Fatalf("prepare: %v %s", err, output)
		}
		switch i {
		case 0:
			created[0] = true
		case 1:
			created[1] = true
		case 5:
			created[2] = true
		}
	}
	probe, err := topology.UserExec(os.Getuid(), os.Getgid(), []string{"curl", "--noproxy", "*", "--max-time", "10", "--fail", "--silent", "--show-error", "--resolve", "example.com:443:" + address.String(), "https://example.com/"})
	if err != nil {
		t.Fatal(err)
	}
	if output, err := run(probe); err == nil {
		t.Fatalf("unapproved target reached upstream: %s", output)
	}
	values := policy.Pending()
	if len(values) != 1 || values[0].Target.Host != "example.com" || values[0].Target.Port != 443 || values[0].Target.Transport != "tcp" {
		t.Fatalf("original target attribution lost: %+v", values)
	}
	if err := policy.Decide(Decision{ID: values[0].ID, Action: "allow", Scope: "run"}); err != nil {
		t.Fatal(err)
	}
	output, err := run(probe)
	if err != nil {
		t.Fatalf("approved transparent retry failed: %v %s", err, output)
	}
	if !strings.Contains(string(output), "Example Domain") {
		t.Fatalf("unexpected fixture response: %s", output)
	}
	t.Log("VETH_HOST_PORT_TRANSPORT_APPROVAL_PASS (proxy settings ignored)")
}
