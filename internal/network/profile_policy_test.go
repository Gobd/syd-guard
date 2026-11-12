package network

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/config"
)

func networkSnapshot(t *testing.T, rules string) config.ProfileSnapshot {
	t.Helper()
	data := fmt.Sprintf(`{"version":1,"name":"dev","files":[],"network":[%s]}`, rules)
	snapshot, err := config.ParseManagedProfileSnapshot("dev", []byte(data))
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

const exampleRule = `{"host":"example.com","port":443,"transport":"tcp"}`

func testBinding(session string) ManagedBinding {
	return ManagedBinding{SessionID: session, ProjectID: "project-id", ProfileName: "dev", SessionGeneration: "generation", StartIdentity: "start-id"}
}
func mustBind(t *testing.T, p *Policy, b ManagedBinding, s config.ProfileSnapshot) AppliedNetworkRevision {
	t.Helper()
	r, err := p.BindManagedProfile(context.Background(), b, s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func mustReplace(t *testing.T, p *Policy, r AppliedNetworkRevision, s config.ProfileSnapshot) AppliedNetworkRevision {
	t.Helper()
	next, err := p.ReplaceManagedProfile(context.Background(), r, s)
	if err != nil {
		t.Fatal(err)
	}
	return next
}

func TestManagedProfileIsolationAndRevision(t *testing.T) {
	p, _ := NewPolicy(t.TempDir() + "/policy.json")
	target, _ := Canonical("example.com", 443)
	p.Check("s", "name", target)
	pending := p.Pending()[0]
	if err := p.Decide(Decision{pending.ID, "allow", "saved"}); err != nil {
		t.Fatal(err)
	}
	runTarget, _ := Canonical("run.example", 443)
	p.Check("s", "name", runTarget)
	if err := p.Decide(Decision{p.Pending()[0].ID, "allow", "run"}); err != nil {
		t.Fatal(err)
	}
	p.Check("s", "name", Target{Host: "other.example", Port: 443, Transport: "tcp"})
	oldPending := p.Pending()[0]
	empty := networkSnapshot(t, "")
	one := networkSnapshot(t, exampleRule)
	first := mustBind(t, p, testBinding("s"), empty)
	if p.Check("s", "name", target) || p.Check("s", "name", runTarget) {
		t.Fatal("legacy grants inherited")
	}
	if !p.Check("other", "name", target) {
		t.Fatal("legacy durable changed")
	}
	if err := p.Decide(Decision{oldPending.ID, "allow", "run"}); err == nil {
		t.Fatal("legacy pending applied")
	}
	if _, err := p.BindManagedProfile(context.Background(), testBinding("s"), one); err == nil {
		t.Fatal("rebound session")
	}
	next := mustReplace(t, p, first, one)
	if !p.Check("s", "name", target) {
		t.Fatal("profile did not allow")
	}
	after := mustReplace(t, p, next, empty)
	again := mustReplace(t, p, after, one)
	if again.Revision != next.Revision || again.Epoch == next.Epoch {
		t.Fatal("ABA not represented")
	}
	if _, err := p.ReplaceManagedProfile(context.Background(), next, empty); err == nil {
		t.Fatal("ABA stale accepted")
	}
	wrong := again
	wrong.Binding.ProjectID = "different"
	if _, err := p.ReplaceManagedProfile(context.Background(), wrong, empty); err == nil {
		t.Fatal("wrong binding accepted")
	}
	wrong = again
	wrong.Revision = strings.Repeat("0", 64)
	if _, err := p.ReplaceManagedProfile(context.Background(), wrong, empty); err == nil {
		t.Fatal("wrong revision accepted")
	}
	p.End("s")
	if p.Check("s", "name", target) {
		t.Fatal("ended session allowed")
	}
	if _, err := p.ReplaceManagedProfile(context.Background(), again, empty); err == nil {
		t.Fatal("ended replace")
	}
	if _, err := p.BindManagedProfile(context.Background(), testBinding("s"), one); err == nil {
		t.Fatal("ended rebind")
	}
}

func TestManagedProfileInvalidReplacementAtomic(t *testing.T) {
	p, _ := NewPolicy("")
	target, _ := Canonical("example.com", 443)
	current := mustBind(t, p, testBinding("s"), networkSnapshot(t, exampleRule))
	cases := []string{
		`{"host":"example.com","port":443,"transport":"tcp"},` + exampleRule,
		`{"host":"example.com","port":443,"transport":"udp"}`,
		`{"host":"service.sydguard.internal","port":443,"transport":"tcp"}`,
	}
	for _, rules := range cases {
		if _, err := p.ReplaceManagedProfile(context.Background(), current, networkSnapshot(t, rules)); err == nil {
			t.Fatalf("accepted %s", rules)
		}
		if !p.Check("s", "name", target) {
			t.Fatal("invalid replacement changed policy")
		}
	}
	if _, err := p.ReplaceManagedProfile(context.Background(), current, config.ProfileSnapshot{}); err == nil {
		t.Fatal("zero snapshot")
	}
	for _, raw := range []string{`{"version":1,"name":"dev","files":[],"network":[{"host":"8.8.8.8","port":443,"transport":"tcp"}]}`, `{"version":1,"name":"dev","files":[],"network":[],"network":[]}`, `{"version":1,"name":"dev","files":[],"network":[{"host":"EXAMPLE.COM","port":443,"transport":"tcp"}]}`} {
		if _, err := config.ParseManagedProfileSnapshot("dev", []byte(raw)); err == nil {
			t.Fatalf("accepted malformed %s", raw)
		}
	}
	// A canceled operation cannot change the currently installed revision.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.ReplaceManagedProfile(ctx, current, networkSnapshot(t, "")); err == nil {
		t.Fatal("canceled replacement")
	}
	if !p.Check("s", "name", target) {
		t.Fatal("canceled replacement changed policy")
	}
}

func TestManagedGatewayLiveCutover(t *testing.T) {
	p, _ := NewPolicy("")
	empty := networkSnapshot(t, "")
	full := networkSnapshot(t, exampleRule)
	applied := mustBind(t, p, testBinding("s"), empty)
	oldDial := dialVettedPublic
	defer func() { dialVettedPublic = oldDial }()
	var calls atomic.Int32
	dialVettedPublic = func(ctx context.Context, target Target) (net.Conn, error) {
		return dialPublicWith(ctx, target, func(_ context.Context, network, host string) ([]netip.Addr, error) {
			if network != "ip" || host != "example.com" {
				t.Errorf("wrong lookup %s %s", network, host)
			}
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		}, func(_ context.Context, network, address string) (net.Conn, error) {
			calls.Add(1)
			if network != "tcp" || address != "8.8.8.8:443" {
				t.Errorf("wrong dial %s %s", network, address)
			}
			a, b := net.Pipe()
			go func() {
				defer func() { _ = b.Close() }()
				_, _ = http.ReadRequest(bufio.NewReader(b))
				_, _ = io.WriteString(b, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
			}()
			return a, nil
		})
	}
	gate, err := Start(p, "s", "work")
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	// HTTP origin requests exercise admission and the vetted dial path.
	get := func() int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, "http://example.com:443/", nil)
		client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(mustURL(t, "http://"+gate.Address))}, Timeout: 2 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.ReadAll(resp.Body)
		return resp.StatusCode
	}
	if got := get(); got != 403 {
		t.Fatalf("initial %d", got)
	}
	applied = mustReplace(t, p, applied, full)
	if got := get(); got != 200 {
		t.Fatalf("allowed %d", got)
	}
	applied = mustReplace(t, p, applied, empty)
	if got := get(); got != 403 {
		t.Fatalf("removed %d", got)
	}
	if calls.Load() != 1 {
		t.Fatalf("unexpected dials %d", calls.Load())
	}
	_ = applied
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestManagedGatewayRevokesInflightDNSAndDial(t *testing.T) {
	for _, stage := range []string{"dns", "dial"} {
		t.Run(stage, func(t *testing.T) {
			p, _ := NewPolicy("")
			applied := mustBind(t, p, testBinding("s"), networkSnapshot(t, exampleRule))
			entered := make(chan struct{})
			release := make(chan struct{})
			peer := make(chan net.Conn, 1)
			canceled := make(chan bool, 1)
			old := dialVettedPublic
			dialVettedPublic = func(ctx context.Context, target Target) (net.Conn, error) {
				return dialPublicWith(ctx, target, func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
					if stage == "dns" {
						close(entered)
						<-release
						canceled <- ctx.Err() != nil
					}
					return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
				}, func(ctx context.Context, _, _ string) (net.Conn, error) {
					if stage == "dial" {
						close(entered)
						<-release
						canceled <- ctx.Err() != nil
					}
					a, b := net.Pipe()
					peer <- b
					return a, nil
				})
			}
			gate, err := Start(p, "s", "work")
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan int, 1)
			go func() {
				client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(mustURL(t, "http://"+gate.Address))}, Timeout: 3 * time.Second}
				resp, e := client.Get("http://example.com:443/")
				if e != nil {
					done <- 0
					return
				}
				defer func() { _ = resp.Body.Close() }()
				done <- resp.StatusCode
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("dial did not start")
			}
			mustReplace(t, p, applied, networkSnapshot(t, ""))
			close(release)
			if !<-canceled {
				t.Error("epoch context was not canceled")
			}
			if status := <-done; status != http.StatusForbidden && status != http.StatusBadGateway {
				t.Errorf("unexpected status %d", status)
			}
			if stage == "dial" {
				b := <-peer
				defer func() { _ = b.Close() }()
				_ = b.SetReadDeadline(time.Now().Add(time.Second))
				buf := make([]byte, 1)
				n, e := b.Read(buf)
				if n != 0 || e != io.EOF {
					t.Errorf("revoked upstream received bytes: %d %v", n, e)
				}
			} else {
				select {
				case b := <-peer:
					_ = b.Close()
					t.Error("dial after DNS revoked")
				default:
				}
			}
			gate.Close()
			dialVettedPublic = old
		})
	}
}

func TestDialPublicRejectsMixedDNSAnswers(t *testing.T) {
	target, _ := Canonical("example.com", 443)
	called := false
	_, err := dialPublicWith(context.Background(), target, func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")}, nil
	}, func(context.Context, string, string) (net.Conn, error) { called = true; return nil, nil })
	if err == nil || called {
		t.Fatal("mixed DNS answers were dialed")
	}
}

func TestManagedTransparentRevokesInflightDial(t *testing.T) {
	p, _ := NewPolicy("")
	applied := mustBind(t, p, testBinding("s"), networkSnapshot(t, exampleRule))
	synthetic := NewSynthetic()
	address, err := synthetic.Address("example.com")
	if err != nil {
		t.Fatal(err)
	}
	oldDestination, oldDial := connectionDestination, dialVettedPublic
	defer func() { connectionDestination, dialVettedPublic = oldDestination, oldDial }()
	connectionDestination = func(*net.TCPConn) (netip.AddrPort, error) { return netip.AddrPortFrom(address, 443), nil }
	entered := make(chan struct{})
	release := make(chan struct{})
	peer := make(chan net.Conn, 1)
	canceled := make(chan bool, 1)
	dialVettedPublic = func(ctx context.Context, _ Target) (net.Conn, error) {
		close(entered)
		<-release
		canceled <- ctx.Err() != nil
		a, b := net.Pipe()
		peer <- b
		return a, nil
	}
	gate, err := StartTransparent(synthetic, p, "s", "work", netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", itoaPort(gate.Address)))
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = conn.Write([]byte("must not reach upstream"))
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("dial did not start")
	}
	mustReplace(t, p, applied, networkSnapshot(t, ""))
	close(release)
	if !<-canceled {
		t.Error("dial was not canceled")
	}
	upstream := <-peer
	_ = upstream.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	n, err := upstream.Read(b[:])
	if n != 0 || err != io.EOF {
		t.Errorf("revoked upstream received bytes %d %v", n, err)
	}
	_ = upstream.Close()
	_ = conn.Close()
	gate.Close()
}

func TestManagedProfilesDoNotCrossSessionsAndTrustedIsSeparate(t *testing.T) {
	p, _ := NewPolicy("")
	target, _ := Canonical("example.com", 443)
	first := mustBind(t, p, testBinding("one"), networkSnapshot(t, exampleRule))
	_ = mustBind(t, p, testBinding("two"), networkSnapshot(t, ""))
	if !p.Check("one", "name", target) || p.Check("two", "name", target) {
		t.Fatal("profile source leaked between sessions")
	}
	for _, pending := range p.Pending() {
		if pending.SessionID == "two" {
			if err := p.Decide(Decision{pending.ID, "allow", "saved"}); err == nil {
				t.Fatal("legacy saved decision accepted")
			}
			if err := p.Decide(Decision{pending.ID, "allow", "run"}); err == nil {
				t.Fatal("legacy run decision accepted")
			}
		}
	}
	if err := p.AllowTrusted("one", target, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	mustReplace(t, p, first, networkSnapshot(t, ""))
	if !p.Check("one", "name", target) || p.Check("two", "name", target) {
		t.Fatal("explicit trusted source not isolated")
	}
}

func TestManagedProfileTargetLimit(t *testing.T) {
	rules := make([]string, 4097)
	for i := range rules {
		rules[i] = fmt.Sprintf(`{"host":"h%d.example.com","port":443,"transport":"tcp"}`, i)
	}
	p, _ := NewPolicy("")
	applied := mustBind(t, p, testBinding("s"), networkSnapshot(t, strings.Join(rules[:4096], ",")))
	data := fmt.Sprintf(`{"version":1,"name":"dev","files":[],"network":[%s]}`, strings.Join(rules, ","))
	if _, err := config.ParseManagedProfileSnapshot("dev", []byte(data)); err == nil {
		t.Fatal("more than 4096 rules accepted")
	}
	target, _ := Canonical("h4095.example.com", 443)
	if !p.Check("s", "name", target) {
		t.Fatal("boundary snapshot was not installed")
	}
	mustReplace(t, p, applied, networkSnapshot(t, ""))
	if p.Check("s", "name", target) {
		t.Fatal("boundary snapshot was not removed")
	}
}
