package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Gobd/syd-guard/internal/system"
)

func TestNormalizePaths(t *testing.T) {
	h := system.Home()
	cases := map[string]string{
		"~/.cache/go/**": h + "/.cache/go/***",
		"/opt/x/":        "/opt/x",
		"/opt/*/bin":     "/opt/*/bin",
	}
	for in, want := range cases {
		got, err := Normalize("read", in)
		if err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"relative/path", "/a/../etc", "/a\nallow/all+/***", "/a\x00b", "", "/a//b"} {
		if _, err := Normalize("write", bad); err == nil {
			t.Errorf("Normalize(%q) should fail", bad)
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
		h, err := ParseHostRule(tc.rule)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.rule, err)
		}
		if got := h.Match(tc.scheme, tc.host, tc.port); got != tc.want {
			t.Errorf("%q match %s://%s:%s = %v, want %v", tc.rule, tc.scheme, tc.host, tc.port, got, tc.want)
		}
	}
	for _, bad := range []string{"https://github.com/path", "ftp://x.com", "user@x.com", "x.com:0", "x.com:99999", "a b", "x.\ncom"} {
		if _, err := Normalize("hosts", bad); err == nil {
			t.Errorf("host rule %q should be rejected", bad)
		}
	}
	if h, _ := ParseHostRule("*.x.com:443"); h.Exact() {
		t.Error("wildcard must not be exact")
	}
	if h, _ := ParseHostRule("https://db.lan"); !h.Exact() {
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
		if got := MatchPath(tc.pat, tc.path); got != tc.want {
			t.Errorf("MatchPath(%q, %q) = %v", tc.pat, tc.path, got)
		}
	}
}

func TestProtection(t *testing.T) {
	h := system.Home()
	p := ProtectedFor("/work/proj", "/work/proj/.sydguard/review.json")
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
		err := p.Check(tc.kind, tc.pat)
		if (err == nil) != tc.ok {
			t.Errorf("check(%s %s) = %v, want ok=%v", tc.kind, tc.pat, err, tc.ok)
		}
	}
}

func TestCompileProfile(t *testing.T) {
	prof, err := CompileProfile(ProfileInput{
		Project: "/work/proj", ProxyPort: 4000, IPC: "@x",
		Protect: ProtectedFor("/work/proj"),
		Rules:   []Rules{{Read: []string{"/ok/**", "/bad\nallow/all+/***"}, Write: []string{system.Home() + "/.ssh/***"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prof, "allow/"+ReadCaps+"+/ok/***") {
		t.Error("valid rule missing")
	}
	if strings.Contains(prof, "/bad") || strings.Contains(prof, "allow/"+WriteCaps+"+"+system.Home()+"/.ssh") {
		t.Error("invalid or protected rule reached the profile")
	}
	if strings.Contains(prof, "allow/all") {
		t.Error("write must not compile to Syd's all")
	}
	lines := strings.Split(strings.TrimSpace(prof), "\n")
	if lines[len(lines)-1] != "lock:ipc" || !strings.HasPrefix(lines[len(lines)-3], "deny/") {
		t.Error("Protection denies must come last, before ipc/lock")
	}
	if _, err := CompileProfile(ProfileInput{Project: "/work/x\nallow/all+/***", IPC: "@x"}); err == nil {
		t.Error("project path with newline must be rejected")
	}
}

func TestNetworkProfileKeepsHelperNamespace(t *testing.T) {
	profile, err := CompileProfile(ProfileInput{Project: "/work/proj", IPC: "@test", Network: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(profile, "unshare/net") {
		t.Fatal("Syd must not replace the helper's network namespace")
	}
	for _, want := range []string{"unshare/user:1", "unshare/mount:1", "passenv+SG_BROKER", "allow/net/connect+::/0!0-65535"} {
		if !strings.Contains(profile, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if strings.Contains(profile, "passenv+*_PROXY") {
		t.Fatal("legacy proxy environment enabled")
	}
}

func TestLearnRoot(t *testing.T) {
	h := system.Home()
	for in, want := range map[string]string{
		h + "/.pi/agent/install/x.js":                h + "/.pi",
		h + "/.local/share/pnpm/store/v11/links/a/b": h + "/.local/share/pnpm",
		h + "/.config/gh/hosts.yml":                  h + "/.config/gh",
		h + "/.gitconfig":                            h + "/.gitconfig",
		h + "/notes.txt":                             h,
		"/workspace/other/src/main.go":               "/workspace/other/src",
	} {
		if got := LearnRoot(in); got != want {
			t.Errorf("LearnRoot(%q) = %q, want %q", in, got, want)
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
		got, err := RulesFileFor(p, p+"/sub", spec)
		if err != nil || got != want {
			t.Errorf("RulesFileFor(%q) = %q, %v; want %q", spec, got, err, want)
		}
	}
	if _, err := RulesFileFor(p, p, ".."); err == nil {
		t.Error("'..' names must fail")
	}
}

func TestStoreTrustAndHardlinks(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	file := filepath.Join(dir, "proj", ".sydguard.json")
	s := NewStore()
	if _, _, err := s.Edit(file, AddRule("hosts", "github.com")); err != nil {
		t.Fatal(err)
	}
	if r := s.Get(file); len(r.Hosts) != 1 {
		t.Fatalf("rules not saved: %+v", r)
	}
	// An outside edit is not used until Trusted.
	if err := os.WriteFile(file, []byte(`{"hosts":["*"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	s.files[file].checked = s.files[file].checked.AddDate(-1, 0, 0)
	v := s.View(file)
	if v.Pending == "" || len(v.Rules.Hosts) != 1 || v.Rules.Hosts[0] != "github.com" {
		t.Fatalf("untrusted edit was used: %+v", v)
	}
	if _, _, err := s.Edit(file, AddRule("hosts", "x.com")); err == nil {
		t.Error("editing over untrusted content must fail")
	}
	if _, after, err := s.TrustCurrent(file); err != nil || after.Hosts[0] != "*" {
		t.Fatalf("Trust: %v %+v", err, after)
	}
	// A second hard link makes the file unusable.
	if err := os.Link(file, filepath.Join(dir, "alias.json")); err != nil {
		t.Skip("no hard links here")
	}
	if _, _, err := ReadRulesFile(file); err == nil || !strings.Contains(err.Error(), "hard links") {
		t.Errorf("hard-linked rules file accepted: %v", err)
	}
}

func TestDiffCommands(t *testing.T) {
	a := Rules{Read: []string{"/a/***", "/b"}, Hosts: []string{"x.com"}}
	b := Rules{Read: []string{"/b", "/c"}, Hosts: []string{"y.com"}}
	got := strings.Join(DiffCommands(a, b), "\n")
	if !strings.Contains(got, "allow/"+ReadCaps+"-/a/***") || !strings.Contains(got, "allow/"+ReadCaps+"+/c") || strings.Contains(got, "/b") || strings.Contains(got, ".com") {
		t.Errorf("diff:\n%s", got)
	}
}
