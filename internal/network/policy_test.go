package network

import (
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"testing"
)

func TestReviewScopePersistenceAndIsolation(t *testing.T) {
	file := filepath.Join(t.TempDir(), "network.json")
	policy, err := NewPolicy(file)
	if err != nil {
		t.Fatal(err)
	}
	target, err := Canonical("API.Example.COM.", 443)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Check("a", "demo", target) {
		t.Fatal("unapproved target allowed")
	}
	pending := policy.Pending()
	if len(pending) != 1 || pending[0].Target.Port != 443 {
		t.Fatal(pending)
	}
	if err := policy.Decide(Decision{pending[0].ID, "allow", "run"}); err != nil {
		t.Fatal(err)
	}
	if !policy.Check("a", "demo", target) || policy.Check("b", "other", target) {
		t.Fatal("run grant leaked or did not apply")
	}
	pending = policy.Pending()
	if err := policy.Decide(Decision{pending[0].ID, "allow", "saved"}); err != nil {
		t.Fatal(err)
	}
	restored, err := NewPolicy(file)
	if err != nil {
		t.Fatal(err)
	}
	if !restored.Check("c", "new", target) {
		t.Fatal("saved host/port intent not restored")
	}
	other, _ := Canonical("api.example.com", 8443)
	if restored.Check("c", "new", other) {
		t.Fatal("port grant broadened")
	}
}

func TestHostnameAndPublicAddressValidation(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "localhost", "*.example.com", "good.com/evil", "x..com", "-x.com", "x.com:443", "user@x.com"} {
		if _, err := Canonical(host, 443); err == nil {
			t.Errorf("accepted %q", host)
		}
	}
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "::1", "::ffff:127.0.0.1", "fc00::1", "2001:db8::1", "192.0.2.1"} {
		if publicAddress(netip.MustParseAddr(ip)) {
			t.Errorf("allowed nonpublic %s", ip)
		}
	}
	if !publicAddress(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("public address refused")
	}
}

func TestGatewayCapturesActualConnectIntent(t *testing.T) {
	policy, err := NewPolicy("")
	if err != nil {
		t.Fatal(err)
	}
	gate, err := Start(policy, "opaque-session", "work")
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close()
	proxy, err := url.Parse("http://" + gate.Address)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	if _, err := client.Get("https://api.example.com:8443/v1/test"); err == nil {
		t.Fatal("unapproved CONNECT succeeded")
	}
	values := policy.Pending()
	if len(values) != 1 || values[0].Target.Host != "api.example.com" || values[0].Target.Port != 8443 || values[0].SessionID != "opaque-session" {
		t.Fatalf("wrong connection candidate: %+v", values)
	}
}
