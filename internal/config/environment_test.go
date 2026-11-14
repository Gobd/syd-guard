package config

import (
	"slices"
	"strings"
	"testing"
)

func TestFilterAgentEnv(t *testing.T) {
	in := []string{"PATH=/bin", "TERM=xterm", "LANG=en_US.UTF-8", "NODE_ENV=test", "API_VERSION=1", "GH_TOKEN=secret-one", "ANTHROPIC_API_KEY=secret-two", "AWS_ACCESS_KEY_ID=secret-three", "PGPASSWORD=secret-four", "SSH_AUTH_SOCK=/agent.sock", "custom_password=secret-five"}
	got, removed := FilterAgentEnv(in, []string{"ANTHROPIC_API_KEY"}, map[string]string{"GH_TOKEN": "explicit-token"})
	for _, want := range in[:5] {
		if !slices.Contains(got, want) {
			t.Errorf("lost normal variable %s", want)
		}
	}
	for _, key := range []string{"GH_TOKEN", "ANTHROPIC_API_KEY"} {
		if slices.Contains(removed, key) {
			t.Errorf("lost explicit opt-in %s", key)
		}
	}
	for _, key := range []string{"AWS_ACCESS_KEY_ID", "PGPASSWORD", "SSH_AUTH_SOCK", "custom_password"} {
		if !slices.Contains(removed, key) {
			t.Errorf("inherited credential was not removed: %s", key)
		}
		for _, item := range got {
			if strings.HasPrefix(item, key+"=") {
				t.Errorf("credential retained: %s", key)
			}
		}
	}
	if strings.Contains(strings.Join(removed, " "), "secret-") {
		t.Fatal("diagnostics disclose values")
	}
}

func TestPassEnvValidation(t *testing.T) {
	for _, name := range []string{"GH_TOKEN", "_NAME", "PATH"} {
		if !ValidPassEnv(name) {
			t.Errorf("valid name rejected: %q", name)
		}
	}
	for _, name := range []string{"", "1NAME", "A=B", "A\nB", "SYD_LOG_FD", "SG_BROKER", "*"} {
		if ValidPassEnv(name) || (Config{PassEnv: []string{name}}).validate() == nil {
			t.Errorf("invalid or reserved name accepted: %q", name)
		}
	}
}

func TestForGuestForwardsOnlyExplicitHostEnv(t *testing.T) {
	t.Setenv("GH_TOKEN", "host-token")
	t.Setenv("OTHER_SECRET", "not-requested")
	cfg := Config{PassEnv: []string{"GH_TOKEN"}}
	guest, err := cfg.ForGuest()
	if err != nil || guest.Env["GH_TOKEN"] != "host-token" {
		t.Fatal("explicit host variable not forwarded", err)
	}
	if _, ok := guest.Env["OTHER_SECRET"]; ok {
		t.Fatal("unrequested host secret forwarded")
	}
	cfg.Env = map[string]string{"GH_TOKEN": "scoped-token"}
	guest, err = cfg.ForGuest()
	if err != nil || guest.Env["GH_TOKEN"] != "scoped-token" {
		t.Fatal("host environment overrode configured value", err)
	}
}
