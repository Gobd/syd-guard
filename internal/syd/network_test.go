package syd

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSyntheticConnectDenial(t *testing.T) {
	base := `{"ctx":"access","cap":"net/connect","act":"deny","sys":"connect","addr":"tcp!198.18.0.2!443","ipv":4,"proto":"tcp"}`
	endpoint, ok := ParseSyntheticConnectDenial([]byte(base))
	if !ok || endpoint.String() != "198.18.0.2:443" {
		t.Fatalf("valid denial: %v %v", endpoint, ok)
	}
	for _, test := range []struct{ old, replacement string }{
		{`"act":"deny"`, `"act":"allow"`},
		{`"ctx":"access"`, `"ctx":"other"`},
		{`"cap":"net/connect"`, `"cap":"net/bind"`},
		{`"sys":"connect"`, `"sys":"sendto"`},
		{`"ipv":4`, `"ipv":6`},
		{`"proto":"tcp"`, `"proto":"udp"`},
		{"tcp!198.18.0.2!443", "udp!198.18.0.2!443"},
		{"tcp!198.18.0.2!443", "tcp!127.0.0.1!443"},
		{"tcp!198.18.0.2!443", "tcp!::ffff:198.18.0.2!443"},
		{"tcp!198.18.0.2!443", "tcp!198.18.0.2!0"},
		{"tcp!198.18.0.2!443", "tcp!198.18.0.2!0443"},
		{"tcp!198.18.0.2!443", "tcp!198.18.0.2!65536"},
		{"tcp!198.18.0.2!443", "tcp!198.18.0.2!443!extra"},
	} {
		data := strings.Replace(base, test.old, test.replacement, 1)
		if _, ok := ParseSyntheticConnectDenial([]byte(data)); ok {
			t.Errorf("accepted %s", data)
		}
	}
	if _, ok := ParseSyntheticConnectDenial([]byte("{")); ok {
		t.Fatal("accepted malformed JSON")
	}
}

func TestGrantSyntheticTCP(t *testing.T) {
	dir, err := os.MkdirTemp("", "sg-ipc-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	socket := filepath.Join(dir, "syd.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	commands := make(chan string, 2)
	go func() {
		for _, response := range []string{`{"err":0,"msg":"ACK"}`, `{"err":1,"msg":"rejected"}`} {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			line, _ := bufio.NewReader(conn).ReadString('\n')
			commands <- line
			_, _ = fmt.Fprintln(conn, response)
			_ = conn.Close()
		}
	}()
	client := IPC{Socket: socket}
	for _, address := range []string{"127.0.0.1:443", "1.1.1.1:443", "[::ffff:198.18.0.2]:443", "198.18.0.2:0"} {
		if err := client.GrantSyntheticTCP(context.Background(), netip.MustParseAddrPort(address)); err == nil {
			t.Errorf("accepted %s", address)
		}
	}
	endpoint := netip.MustParseAddrPort("198.18.0.2:443")
	if err := client.GrantSyntheticTCP(context.Background(), endpoint); err != nil {
		t.Fatal(err)
	}
	if command := <-commands; command != "allow/net/connect+tcp!198.18.0.2!443\n" {
		t.Fatalf("unexpected IPC command: %q", command)
	}
	if err := client.GrantSyntheticTCP(context.Background(), endpoint); err == nil {
		t.Fatal("ignored rejected IPC grant")
	}
	<-commands
}
