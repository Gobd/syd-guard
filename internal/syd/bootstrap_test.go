package syd

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/Gobd/syd-guard/internal/config"
)

func TestBootstrapRulesAreRuntimeOnlyAndLogged(t *testing.T) {
	rules := bootstrapRules()
	for _, want := range []string{"log/rlimit_interval:0", "allow/lock/read,readdir,write", "warn/read,stat,readdir"} {
		if !strings.Contains(rules, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestRunBootstrapRejectsUntrustedCombinations(t *testing.T) {
	start := func(string, []string) error { return nil }
	log := func(io.Reader) error { return nil }
	for _, options := range []RunOptions{
		{Bootstrap: true},
		{Bootstrap: true, OnBootstrapStart: start, OnTrustedLog: log, Scopes: []string{"/tmp"}},
		{Bootstrap: true, OnBootstrapStart: start, OnTrustedLog: log, ResolvedProfile: &config.ResolvedProfile{}},
		{Bootstrap: true, OnBootstrapStart: start, OnTrustedLog: log, OnEvent: func([]byte) error { return nil }},
		{Bootstrap: true, OnBootstrapStart: start, OnTrustedLog: log, Gateway: "127.0.0.1:1234"},
		{Bootstrap: true, OnBootstrapStart: start, OnTrustedLog: log, TransitDNS: "10.232.1.1"},
		{OnTrustedLog: log},
	} {
		if _, err := Run(context.Background(), options); err == nil {
			t.Errorf("accepted invalid bootstrap combination: %+v", options)
		}
	}
}
