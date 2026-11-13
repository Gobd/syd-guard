package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizePaths(t *testing.T) {
	h := home()
	cases := map[string]string{
		"~/.cache/go/**": h + "/.cache/go/***",
		"/opt/x/":        "/opt/x",
		"/opt/*/bin":     "/opt/*/bin",
	}
	for in, want := range cases {
		got, err := normalize("read", in)
		if err != nil || got != want {
			t.Errorf("normalize(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"relative/path", "/a/../etc", "/a\nallow/all+/***", "/a\x00b", "", "/a//b"} {
		if _, err := normalize("write", bad); err == nil {
			t.Errorf("normalize(%q) should fail", bad)
		}
	}
}

func TestHostRules(t *testing.T) {
	type c struct {
		rule, scheme, host, port string
		want                     bool
	}
	for _, tc := range []c{
		{"github.com", "https", "github.com", "443", true},
		{"github.com", "tcp", "github.com", "22", true},
		{"https://github.com", "https", "github.com", "443", true},
		{"https://github.com", "tcp", "github.com", "8443", false},
		{"https://github.com", "http", "github.com", "80", false},
		{"http://example.com:8080", "http", "example.com", "8080", true},
		{"http://example.com:8080", "http", "example.com", "80", false},
		{"*.github.com", "https", "api.github.com", "443", true},
		{"*.github.com", "https", "github.com", "443", false},
		{"*.github.com", "https", "evilgithub.com", "443", false},
		{"tcp://db.example.com:5432", "tcp", "db.example.com", "5432", true},
		{"tcp://db.example.com:5432", "http", "db.example.com", "5432", false},
		{"github.com:443", "https", "GitHub.com.", "443", true},
	} {
		h, err := parseHostRule(tc.rule)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.rule, err)
		}
		if got := h.match(tc.scheme, tc.host, tc.port); got != tc.want {
			t.Errorf("%q match %s://%s:%s = %v, want %v", tc.rule, tc.scheme, tc.host, tc.port, got, tc.want)
		}
	}
	for _, bad := range []string{"https://github.com/path", "ftp://x.com", "user@x.com", "x.com:0", "x.com:99999", "a b", "x.\ncom"} {
		if _, err := normalize("hosts", bad); err == nil {
			t.Errorf("host rule %q should be rejected", bad)
		}
	}
	if h, _ := parseHostRule("*.x.com:443"); h.exact() {
		t.Error("wildcard must not be exact")
	}
	if h, _ := parseHostRule("https://db.lan"); !h.exact() {
		t.Error("https://host should be exact")
	}
}

func TestGlob(t *testing.T) {
	for _, tc := range []struct {
		pat, path string
		want      bool
	}{
		{"/a/***", "/a", true},
		{"/a/***", "/a/b/c", true},
		{"/a/***", "/ab", false},
		{"/a/*", "/a/b", true},
		{"/a/*", "/a/b/c", false},
		{"/a/**/x", "/a/b/c/x", true},
		{"/a.b", "/aXb", false},
	} {
		if got := matchPath(tc.pat, tc.path); got != tc.want {
			t.Errorf("matchPath(%q, %q) = %v", tc.pat, tc.path, got)
		}
	}
}

func TestProtection(t *testing.T) {
	h := home()
	p := protectedFor("/work/proj", "/work/proj/.sydguard/review.json")
	for _, tc := range []struct {
		kind, pat string
		ok        bool
	}{
		{"read", h + "/.ssh/id_ed25519", false},
		{"read", h + "/***", false},
		{"read", h + "/.pi/***", true},
		{"write", h + "/.local/bin/***", false},
		{"read", h + "/.local/bin/pi", true},
		{"write", "/work/proj/.sydguard.json", false},
		{"write", "/work/proj/***", false},
		{"write", "/work/proj/src/***", true},
		{"write", "/work/proj/.git/hooks/pre-commit", false},
		{"write", "/work/proj/.sydguard/review.json", false},
		{"write", "/***", false},
	} {
		err := p.check(tc.kind, tc.pat)
		if (err == nil) != tc.ok {
			t.Errorf("check(%s %s) = %v, want ok=%v", tc.kind, tc.pat, err, tc.ok)
		}
	}
}

func TestCompileProfile(t *testing.T) {
	prof, err := compileProfile(profileInput{Project: "/work/proj", ProxyPort: 4000, IPC: "@x",
		Protect: protectedFor("/work/proj"),
		Rules:   []Rules{{Read: []string{"/ok/**", "/bad\nallow/all+/***"}, Write: []string{home() + "/.ssh/***"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prof, "allow/"+readCaps+"+/ok/***") {
		t.Error("valid rule missing")
	}
	if strings.Contains(prof, "/bad") || strings.Contains(prof, "allow/"+writeCaps+"+"+home()+"/.ssh") {
		t.Error("invalid or protected rule reached the profile")
	}
	if strings.Contains(prof, "allow/all") {
		t.Error("write must not compile to Syd's all")
	}
	lines := strings.Split(strings.TrimSpace(prof), "\n")
	if lines[len(lines)-1] != "lock:ipc" || !strings.HasPrefix(lines[len(lines)-3], "deny/") {
		t.Error("protection denies must come last, before ipc/lock")
	}
	if _, err := compileProfile(profileInput{Project: "/work/x\nallow/all+/***", IPC: "@x"}); err == nil {
		t.Error("project path with newline must be rejected")
	}
}

func TestLearnRoot(t *testing.T) {
	h := home()
	for in, want := range map[string]string{
		h + "/.pi/agent/install/x.js":                h + "/.pi",
		h + "/.local/share/pnpm/store/v11/links/a/b": h + "/.local/share/pnpm",
		h + "/.config/gh/hosts.yml":                  h + "/.config/gh",
		h + "/.gitconfig":                            h + "/.gitconfig",
		h + "/notes.txt":                             h,
		"/workspace/other/src/main.go":               "/workspace/other/src",
	} {
		if got := learnRoot(in); got != want {
			t.Errorf("learnRoot(%q) = %q, want %q", in, got, want)
		}
	}
}

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

func TestRulesFileFor(t *testing.T) {
	p := "/work/proj"
	for spec, want := range map[string]string{
		"":            "/work/proj/.sydguard.json",
		"review":      "/work/proj/.sydguard/review.json",
		"./x.json":    "/work/proj/sub/x.json",
		"/etc/r.json": "/etc/r.json",
	} {
		got, err := rulesFileFor(p, p+"/sub", spec)
		if err != nil || got != want {
			t.Errorf("rulesFileFor(%q) = %q, %v; want %q", spec, got, err, want)
		}
	}
	if _, err := rulesFileFor(p, p, ".."); err == nil {
		t.Error("'..' names must fail")
	}
}

func TestStoreTrustAndHardlinks(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	file := filepath.Join(dir, "proj", ".sydguard.json")
	s := newRuleStore()
	if _, _, err := s.edit(file, addRule("hosts", "github.com")); err != nil {
		t.Fatal(err)
	}
	if r := s.get(file); len(r.Hosts) != 1 {
		t.Fatalf("rules not saved: %+v", r)
	}
	// An outside edit is not used until trusted.
	if err := os.WriteFile(file, []byte(`{"hosts":["*"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	s.files[file].checked = s.files[file].checked.AddDate(-1, 0, 0)
	v := s.view(file)
	if v.Pending == "" || len(v.Rules.Hosts) != 1 || v.Rules.Hosts[0] != "github.com" {
		t.Fatalf("untrusted edit was used: %+v", v)
	}
	if _, _, err := s.edit(file, addRule("hosts", "x.com")); err == nil {
		t.Error("editing over untrusted content must fail")
	}
	if _, after, err := s.trustCurrent(file); err != nil || after.Hosts[0] != "*" {
		t.Fatalf("trust: %v %+v", err, after)
	}
	// A second hard link makes the file unusable.
	if err := os.Link(file, filepath.Join(dir, "alias.json")); err != nil {
		t.Skip("no hard links here")
	}
	if _, _, err := readRulesFile(file); err == nil || !strings.Contains(err.Error(), "hard links") {
		t.Errorf("hard-linked rules file accepted: %v", err)
	}
}

func TestDiffCommands(t *testing.T) {
	a := Rules{Read: []string{"/a/***", "/b"}, Hosts: []string{"x.com"}}
	b := Rules{Read: []string{"/b", "/c"}, Hosts: []string{"y.com"}}
	got := strings.Join(diffCommands(a, b), "\n")
	if !strings.Contains(got, "allow/"+readCaps+"-/a/***") || !strings.Contains(got, "allow/"+readCaps+"+/c") || strings.Contains(got, "/b") || strings.Contains(got, ".com") {
		t.Errorf("diff:\n%s", got)
	}
}

func TestParseArgs(t *testing.T) {
	o, err := parse([]string{"--rules", "review", "--vm=dev", "--", "lambdap", "pi", "--model", "x"})
	if err != nil || o.rules != "review" || o.vm != "dev" || strings.Join(o.args, " ") != "lambdap pi --model x" {
		t.Errorf("parse: %+v %v", o, err)
	}
	o, _ = parse([]string{"lambdap", "pi"})
	if strings.Join(o.args, " ") != "lambdap pi" {
		t.Errorf("bare command: %+v", o)
	}
}
