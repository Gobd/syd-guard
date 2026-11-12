package netns

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestVethRedirectAndDefaultDropIntegration(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("SYDGUARD_NETNS_INTEGRATION") != "1" {
		t.Skip("explicit disposable Linux namespace test requires sudo")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	topology, err := New()
	if err != nil {
		t.Fatal(err)
	}
	dns, err := net.Listen("tcp4", "0.0.0.0:0") //nolint:gosec // short-lived test-only data listener must receive the veth redirect; no operator API
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dns.Close() }()
	tcp, err := net.Listen("tcp4", "0.0.0.0:0") //nolint:gosec // short-lived test-only data listener must receive the veth redirect; no operator API
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tcp.Close() }()
	dnsPort, err := portOf(dns)
	if err != nil {
		t.Fatal(err)
	}
	tcpPort, err := portOf(tcp)
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan string, 2)
	for label, listener := range map[string]net.Listener{"dns": dns, "synthetic-tcp": tcp} {
		go func(label string, listener net.Listener) {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			reader := bufio.NewReader(conn)
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if line == "\r\n" {
					break
				}
			}
			_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", len(label), label)
			received <- label
		}(label, listener)
	}
	run := func(command Command) ([]byte, error) {
		argv := append([]string{"-n", command.Program}, command.Args...)
		process := exec.CommandContext(ctx, "sudo", argv...) //nolint:gosec // generated bounded session-resource commands; explicit integration opt-in
		process.Stdin = strings.NewReader(command.Input)
		return process.CombinedOutput()
	}
	cleanup, err := topology.Cleanup()
	if err != nil {
		t.Fatal(err)
	}
	created := [3]bool{} // namespace, veth, nft table; never remove a resource we failed to create
	defer func() {
		for i, command := range cleanup {
			if !created[2-i] {
				continue
			}
			argv := append([]string{"-n", command.Program}, command.Args...)
			_ = exec.Command("sudo", argv...).Run() //nolint:gosec // generated test-owned cleanup must survive context cancellation
		}
	}()
	commands, err := topology.Prepare(dnsPort, tcpPort)
	if err != nil {
		t.Fatal(err)
	}
	for i, command := range commands {
		if output, err := run(command); err != nil {
			t.Fatalf("%s %v: %v %s", command.Program, command.Args, err, output)
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
	// curl ignores every proxy env and uses a direct socket. The redirect still
	// catches synthetic destinations. Both loopback and public-IP egress fail.
	for _, probe := range []struct {
		address string
		allowed bool
	}{
		{"http://198.18.0.10:8443", true},
		{"http://" + topology.Host.String() + ":53", true},
		{"http://1.1.1.1:443", false},
		{"http://" + topology.Host.String() + ":22", false},
		{"http://" + topology.Host.String() + ":" + strconv.Itoa(int(dnsPort)), false},
		{"http://" + topology.Host.String() + ":" + strconv.Itoa(int(tcpPort)), false},
	} {
		command, err := topology.UserExec(os.Getuid(), os.Getgid(), []string{"curl", "--noproxy", "*", "--max-time", "1", "--http0.9", probe.address})
		if err != nil {
			t.Fatal(err)
		}
		output, err := run(command)
		if probe.allowed && err != nil {
			t.Fatalf("redirect failed %s: %v %s", probe.address, err, output)
		}
		if !probe.allowed && err == nil {
			t.Fatalf("unapproved route bypassed drop: %s", probe.address)
		}
	}
	for i := 0; i < 2; i++ {
		select {
		case label := <-received:
			t.Logf("captured %s", label)
		case <-ctx.Done():
			t.Fatal("expected data-plane redirect missing")
		}
	}
}

func portOf(listener net.Listener) (uint16, error) {
	_, text, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(text, 10, 16)
	return uint16(value), err
}

func TestVethTableCollisionIntegration(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("SYDGUARD_NETNS_INTEGRATION") != "1" {
		t.Skip("explicit disposable Linux namespace test requires sudo")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	topology, err := New()
	if err != nil {
		t.Fatal(err)
	}
	run := func(command Command) ([]byte, error) {
		argv := append([]string{"-n", command.Program}, command.Args...)
		process := exec.CommandContext(ctx, "sudo", argv...) //nolint:gosec // generated test-owned names and commands
		process.Stdin = strings.NewReader(command.Input)
		return process.CombinedOutput()
	}
	if output, err := run(Command{Program: "nft", Args: []string{"create", "table", "inet", topology.Table}}); err != nil {
		t.Fatalf("create test-owned colliding table: %v %s", err, output)
	}
	created := [2]bool{}
	defer func() {
		cleanup := []Command{{Program: "ip", Args: []string{"link", "del", topology.HostLink}}, {Program: "ip", Args: []string{"netns", "del", topology.Namespace}}}
		for i, command := range cleanup {
			if created[1-i] {
				argv := append([]string{"-n", command.Program}, command.Args...)
				_ = exec.Command("sudo", argv...).Run() //nolint:gosec // test-owned resources only
			}
		}
		_ = exec.Command("sudo", "-n", "nft", "delete", "table", "inet", topology.Table).Run() //nolint:gosec // table created by this test
	}()
	commands, err := topology.Prepare(53001, 53002)
	if err != nil {
		t.Fatal(err)
	}
	for i, command := range commands[:6] {
		output, err := run(command)
		if i == 5 {
			if err == nil {
				t.Fatal("nft table collision unexpectedly succeeded")
			}
			break
		}
		if err != nil {
			t.Fatalf("prepare: %v %s", err, output)
		}
		if i < 2 {
			created[i] = true
		}
	}
	if output, err := run(Command{Program: "nft", Args: []string{"list", "table", "inet", topology.Table}}); err != nil {
		t.Fatalf("colliding table was removed: %v %s", err, output)
	}
}
