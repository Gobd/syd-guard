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
	"time"

	"github.com/Gobd/syd-guard/internal/api"
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
func TestProxyDoesNotResolveBeforeApproval(t *testing.T) {
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

func TestDNSGrantsExpire(t *testing.T) {
	now := time.Now()
	grants := map[string]map[string]time.Time{
		"tcp://db.example.com:5432": {"10.0.0.5!5432": now.Add(-time.Second), "10.0.0.6!5432": now.Add(time.Minute)},
		"example.com":               {"93.184.216.34!0-65535": now.Add(-time.Minute)},
	}
	cmds := expireGrants(grants, now)
	if len(cmds) != 2 || len(grants) != 1 || len(grants["tcp://db.example.com:5432"]) != 1 {
		t.Fatalf("expired %v, left %v", cmds, grants)
	}
	if clampTTL(5) != minGrantTTL || clampTTL(86400) != maxGrantTTL || clampTTL(300) != 5*time.Minute {
		t.Error("TTL clamp")
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

func TestTunnelServerNameMustMatch(t *testing.T) {
	if err := checkTunnel(helloFor(t, "github.com"), "github.com", nil); err != nil {
		t.Errorf("matching name refused: %v", err)
	}
	if err := checkTunnel(helloFor(t, "evil.example"), "github.com", nil); err == nil {
		t.Error("domain fronting allowed")
	}
	plain := bufio.NewReader(strings.NewReader("GET / HTTP/1.1\r\n\r\n"))
	if err := checkTunnel(plain, "github.com", nil); err == nil {
		t.Error("non-TLS tunnel allowed without a tcp:// rule")
	}
	tcp, _ := policy.ParseHostRule("tcp://db.example.com:5432")
	plain = bufio.NewReader(strings.NewReader("PGSQL..."))
	if err := checkTunnel(plain, "db.example.com", []policy.HostRule{tcp}); err != nil {
		t.Errorf("tcp:// rule should allow raw tunnels: %v", err)
	}
}
