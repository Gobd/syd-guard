package syd

import (
	"strings"
	"testing"
)

func TestTransparentRulesRestrictResolver(t *testing.T) {
	rules, err := TransparentRules("10.232.12.1")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"allow/net/connect+tcp!10.232.12.1!53\n", "allow/net/connect+udp!10.232.12.1!53\n", "allow/lock/connect+1-65535\n"} {
		if !strings.Contains(rules, want) {
			t.Fatalf("missing %q: %s", want, rules)
		}
	}
	if strings.Contains(rules, "198.18") {
		t.Fatal("synthetic endpoint granted before approval")
	}
	for _, invalid := range []string{"127.0.0.1", "10.233.0.1", "::1", "10.232.1.1\nlock:off"} {
		if _, err := TransparentRules(invalid); err == nil {
			t.Errorf("accepted %q", invalid)
		}
	}
}
