package guest

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/Gobd/syd-guard/internal/api"
	"github.com/Gobd/syd-guard/internal/policy"
	"golang.org/x/net/dns/dnsmessage"
)

func networkFixture(t *testing.T) (*Daemon, *Session) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	if err := os.MkdirAll(sessionsDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	s := &Session{ID: "test", RulesFile: filepath.Join(t.TempDir(), ".sydguard.json")}
	d := &Daemon{sessions: map[string]*Session{s.ID: s}, cards: map[string]*Card{}, store: policy.NewStore(), events: api.NewBroadcaster()}
	if err := d.startDNS(s); err != nil {
		t.Fatal(err)
	}
	return d, s
}

func TestSyntheticDNSNeedsNoBroadGrantAndSurvivesRestart(t *testing.T) {
	d, s := networkFixture(t)
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.TypeTXT} {
		q := dnsmessage.Message{Header: dnsmessage.Header{ID: 42}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("unapproved.example."), Type: typ, Class: dnsmessage.ClassINET}}}
		wire, err := q.Pack()
		if err != nil {
			t.Fatal(err)
		}
		var answer dnsmessage.Message
		if err := answer.Unpack(s.dns.handle(wire, "udp")); err != nil {
			t.Fatal(err)
		}
		if typ == dnsmessage.TypeTXT {
			if answer.RCode != dnsmessage.RCodeRefused {
				t.Fatal("unapproved upstream query permitted")
			}
			continue
		}
		if answer.RCode != dnsmessage.RCodeSuccess || len(answer.Answers) != 1 {
			t.Fatalf("synthetic response: %+v", answer)
		}
		var ip netip.Addr
		switch body := answer.Answers[0].Body.(type) {
		case *dnsmessage.AResource:
			ip = netip.AddrFrom4(body.A)
		case *dnsmessage.AAAAResource:
			ip = netip.AddrFrom16(body.AAAA)
		default:
			t.Fatal("unexpected answer")
		}
		if s.dns.nameOf(ip.String()) != "unapproved.example" {
			t.Fatal("identity lost")
		}
		if err := d.startDNS(s); err != nil {
			t.Fatal(err)
		}
		if s.dns.nameOf(ip.String()) != "unapproved.example" {
			t.Fatal("cached identity lost on restart")
		}
	}
	if len(d.cards) != 0 {
		t.Fatal("synthetic lookup asked for a broad name grant")
	}
	if got := d.store.Get(s.RulesFile); len(got.Hosts) != 0 {
		t.Fatal("synthetic lookup changed policy")
	}
}

func TestBrokerIsNotAForwardProxy(t *testing.T) {
	d, s := networkFixture(t)
	if err := d.startBroker(s); err != nil {
		t.Fatal(err)
	}
	defer d.stopServers(s)
	for _, request := range []string{
		"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
		"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
	} {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", s.ProxyPort))
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Write([]byte(request))
		if err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		_ = c.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatalf("forward proxy still enabled: %d", response.StatusCode)
		}
	}
	if len(d.cards) != 0 {
		t.Fatal("proxy request reached egress policy")
	}
}

func TestProtocolScopedRawGrant(t *testing.T) {
	d, s := networkFixture(t)
	if _, _, err := d.store.Edit(s.RulesFile, policy.AddRule("connect", "udp!93.184.216.34!9000")); err != nil {
		t.Fatal(err)
	}
	n := newNetwork(d, s)
	defer n.close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := n.dialTarget(ctx, "udp", "udp", "93.184.216.34", "9000"); err != nil {
		t.Fatal(err)
	}
	if _, err := n.dialTarget(ctx, "tcp", "tcp", "93.184.216.34", "9000"); err == nil {
		t.Fatal("UDP grant authorized TCP")
	}
	if _, err := n.dialTarget(ctx, "udp", "udp", "93.184.216.34", "9001"); err == nil {
		t.Fatal("grant authorized another port")
	}
}
