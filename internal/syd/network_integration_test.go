package syd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestNetworkDenialAndLiveGrantIntegration probes upstream's trusted network
// denial log and the immutable Landlock port ceiling before wiring a broker.
func TestNetworkDenialAndLiveGrantIntegration(t *testing.T) {
	engine := os.Getenv("SYDGUARD_TEST_SYD")
	if runtime.GOOS != "linux" || engine == "" {
		t.Skip("requires Linux and explicit tested Syd")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	port := listener.Addr().(*net.TCPAddr).Port
	work, temporary := t.TempDir(), t.TempDir()
	authority, err := os.MkdirTemp("", "sg-net-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(authority) }()
	profile, err := Profile(work, temporary, []string{authority})
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(authority, "syd.sock")
	profile += fmt.Sprintf("allow/lock/connect+1-65535\nipc:%s\nlock:ipc\n", socket)
	profilePath := filepath.Join(authority, "profile.syd-3")
	if err := os.WriteFile(profilePath, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	logRead, logWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logRead.Close(); _ = logWrite.Close() }()
	logData := make(chan []byte, 1)
	go func() { data, _ := io.ReadAll(logRead); logData <- data }()
	script := `set -eu
if curl --noproxy '*' --connect-timeout 1 -s "$1"; then exit 80; fi
printf ready > ready
while [ ! -f continue ]; do /bin/sleep 0.05; done
curl --noproxy '*' --connect-timeout 2 -s "$1" > result
`
	command := exec.CommandContext(ctx, engine, "-P", profilePath, "--", "/bin/sh", "-c", script, "fixture", fmt.Sprintf("http://127.0.0.1:%d", port)) //nolint:gosec // fixed test fixture, generated local address
	command.Dir = work
	command.Env = append(os.Environ(), "SYD_LOG_FD=3")
	command.ExtraFiles = []*os.File{logWrite}
	var output strings.Builder
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = logWrite.Close()
	defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(work, "ready")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no initial denial")
		}
		time.Sleep(20 * time.Millisecond)
	}
	client := IPC{Socket: socket}
	var ack struct {
		Err     int    `json:"err"`
		Message string `json:"msg"`
	}
	if err := client.exchange(ctx, fmt.Sprintf("allow/net/connect+tcp!127.0.0.1!%d", port), &ack); err != nil || ack.Err != 0 || ack.Message != "ACK" {
		t.Fatalf("network IPC grant: %+v %v", ack, err)
	}
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer func() { _ = conn.Close() }()
			_, _ = io.WriteString(conn, "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
		}
	}()
	if err := os.WriteFile(filepath.Join(work, "continue"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("approved retry failed: %v %s", err, output.String())
	}
	data := <-logData
	decoder := json.NewDecoder(bytes.NewReader(data))
	found := false
	for {
		var event struct {
			Context    string `json:"ctx"`
			Capability string `json:"cap"`
			Action     string `json:"act"`
			Syscall    string `json:"sys"`
			Address    string `json:"addr"`
			IPVersion  int    `json:"ipv"`
			Protocol   string `json:"proto"`
		}
		if err := decoder.Decode(&event); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if event.Context == "access" && event.Capability == "net/connect" && event.Action == "deny" && event.Syscall == "connect" && event.Address == fmt.Sprintf("tcp!127.0.0.1!%d", port) && event.IPVersion == 4 && event.Protocol == "tcp" {
			found = true
		}
	}
	if !found {
		t.Fatalf("trusted connect denial missing: %s", data)
	}
	result, err := os.ReadFile(filepath.Join(work, "result")) //nolint:gosec // test-owned output
	if err != nil || string(result) != "ok" {
		t.Fatalf("retry result %q: %v", result, err)
	}
}
