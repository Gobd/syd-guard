package guest

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Gobd/syd-guard/internal/api"
	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/policy"
)

func TestAddrClass(t *testing.T) {
	for ip, want := range map[string]string{
		"127.0.0.1": "blocked", "::1": "blocked", "169.254.169.254": "blocked", "0.0.0.0": "blocked",
		"10.1.2.3": "private", "192.168.5.2": "private", "100.64.1.1": "private", "fd00::1": "private",
		"93.184.216.34": "public", "2606:4700::1": "public", "::ffff:127.0.0.1": "blocked",
	} {
		if got := addrClass(netip.MustParseAddr(ip)); got != want {
			t.Errorf("addrClass(%s) = %s, want %s", ip, got, want)
		}
	}
}

// An unapproved name must never be resolved (that would leak data via DNS).
func TestEgressDoesNotResolveBeforeApproval(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	lookups := 0
	orig := resolve
	resolve = func(context.Context, string) ([]netip.Addr, error) {
		lookups++
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	defer func() { resolve = orig }()
	rules := filepath.Join(home, "p", ".sydguard.json")
	d := &Daemon{sessions: map[string]*Session{}, cards: map[string]*Card{}, store: policy.NewStore(), events: api.NewBroadcaster()}
	s := &Session{ID: "s1", RulesFile: rules, Project: filepath.Dir(rules)}
	d.sessions[s.ID] = s
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // nobody answers the card
	if _, _, err := d.decide(ctx, s, "https", "secret-data.attacker.example", "443"); err == nil {
		t.Fatal("unapproved host was allowed")
	}
	if lookups != 0 {
		t.Fatalf("unapproved name was resolved %d times", lookups)
	}
	if _, _, err := d.store.Edit(rules, policy.AddRule("hosts", "https://example.com")); err != nil {
		t.Fatal(err)
	}
	if addr, _, err := d.decide(context.Background(), s, "https", "example.com", "443"); err != nil || addr != "93.184.216.34:443" || lookups != 1 {
		t.Fatalf("approved host: %q %v (lookups %d)", addr, err, lookups)
	}
}

// helloFor captures a real TLS ClientHello for serverName.
func helloFor(t *testing.T, serverName string) *bufio.Reader {
	t.Helper()
	a, b := net.Pipe()
	go func() {
		_ = tls.Client(a, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}).Handshake() //nolint:gosec // test fixture
	}()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return bufio.NewReaderSize(b, 5+16<<10)
}

func TestTransparentWebIdentity(t *testing.T) {
	if scheme, _, name, err := sniffWeb(helloFor(t, "github.com"), "github.com", "443"); err != nil || scheme != "https" || name != "github.com" {
		t.Fatalf("matching TLS: %q %q %v", scheme, name, err)
	}
	if _, _, _, err := sniffWeb(helloFor(t, "evil.example"), "github.com", "443"); err == nil {
		t.Fatal("mismatched TLS SNI allowed")
	}
	for _, tc := range []struct {
		input, port, scheme string
		denied              bool
	}{
		{"GET / HTTP/1.1\r\nHost: github.com\r\n\r\n", "80", "tcp", false},
		{"GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n", "80", "", true},
		{"PGSQL...", "443", "tcp", false},
	} {
		in := bufio.NewReader(strings.NewReader(tc.input))
		scheme, _, _, err := sniffWeb(in, "github.com", tc.port)
		if (err != nil) != tc.denied || scheme != tc.scheme {
			t.Errorf("%q: %q %v", tc.input, scheme, err)
		}
		b, _ := in.Peek(len(tc.input))
		if string(b) != tc.input {
			t.Fatal("inspection consumed traffic")
		}
	}
}

func TestValidEnvName(t *testing.T) {
	for name, want := range map[string]bool{"ANTHROPIC_BASE_URL": true, "a1": true, "": false, "1A": false, "A=B": false, "A B": false, "A*": false} {
		if config.ValidPassEnv(name) != want {
			t.Errorf("ValidPassEnv(%q) != %v", name, want)
		}
	}
}
