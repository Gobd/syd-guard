package learning

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Gobd/syd-guard/internal/config"
)

func testCollector(t *testing.T) (*Collector, string) {
	t.Helper()
	base := t.TempDir()
	tmp := filepath.Join(base, "runtime")
	policy := filepath.Join(base, ".sydguard")
	c, err := New(Policy{Name: "test", Temporary: tmp, PolicyDirectory: policy, RateLimitDisabled: true})
	if err != nil {
		t.Fatal(err)
	}
	return c, base
}

func event(path, cap string) string {
	return fmt.Sprintf(`{"ctx":"access","act":"warn","path":%q,"cap":%s}`+"\n", path, cap)
}

func collect(t *testing.T, c *Collector, s string) ProfileCandidate {
	t.Helper()
	if err := c.Drain(strings.NewReader(s)); err != nil {
		t.Fatal(err)
	}
	c.FinishOutcome(Outcome{})
	return c.Snapshot()
}

func TestWarnCapabilitiesAndRename(t *testing.T) {
	c, base := testCollector(t)
	src, dst := filepath.Join(base, "src"), filepath.Join(base, "dst")
	s := event(src, `["read","write","truncate","chmod","chattr","delete","rename"]`) + event(dst, `"create"`) + event(src, `"read"`)
	got := collect(t, c, s)
	if got.Incomplete || got.Kind != "permission-check-candidate" {
		t.Fatalf("%+v", got)
	}
	want := map[string][]string{src: {"read", "write", "delete"}, dst: {"write"}}
	for _, r := range got.Profile.Files {
		if r.Recursive || !reflect.DeepEqual(r.Access, want[r.Path]) {
			t.Fatalf("unexpected rule: %+v", r)
		}
		delete(want, r.Path)
	}
	if len(want) != 0 {
		t.Fatal(want)
	}
	if err := config.ValidateProfile("test", got.Profile); err != nil {
		t.Fatal(err)
	}
}

func TestShapesSafetyAndNoRawFields(t *testing.T) {
	c, base := testCollector(t)
	valid := filepath.Join(base, "allowed")
	secret := filepath.Join(base, ".env")
	temp := filepath.Join(base, "runtime", "x")
	if err := os.WriteFile(secret, []byte("hidden"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	lines := fmt.Sprintf(`{"ctx":"access","act":"warn","path":%q,"cap":"read","cmd":"SECRET_CANARY","env":"SECRET_CANARY"}`+"\n", valid) + event(secret, `"write"`) + event(filepath.Join(base, "link"), `"read"`) + event(temp, `"read"`) +
		fmt.Sprintf(`{"ctx":"other","act":"warn","path":%q,"cap":"read","cmd":"SECRET_CANARY"}`+"\n", valid) +
		fmt.Sprintf(`{"ctx":"access","act":"deny","path":%q,"cap":"read"}`+"\n", valid) +
		fmt.Sprintf(`{"ctx":"access","act":"warn","path":%q,"cap":"write","version":2}`+"\n", filepath.Join(base, "version")) +
		fmt.Sprintf(`{"ctx":"access","act":"warn","path":%q,"cap":"read","cap":"write"}`+"\n", valid) +
		event(filepath.Join(base, "wild*"), `"read"`) + event(valid, `["write","unrecognized"]`)
	got := collect(t, c, lines)
	if !got.Incomplete || len(got.Profile.Files) != 1 || !reflect.DeepEqual(got.Profile.Files[0].Access, []string{"read"}) {
		t.Fatalf("%+v", got)
	}
	encoded, _ := json.Marshal(got)
	if strings.Contains(string(encoded), "SECRET_CANARY") || strings.Contains(string(encoded), ".env") {
		t.Fatalf("leaked data: %s", encoded)
	}
	for _, reason := range []string{"unsupported-log-version", "malformed-log", "invalid-path", "unsupported-capability"} {
		if !strings.Contains(strings.Join(got.Reasons, ","), reason) {
			t.Errorf("missing %s: %v", reason, got.Reasons)
		}
	}
}

func TestLossDrainingAndLifecycle(t *testing.T) {
	c, base := testCollector(t)
	p := filepath.Join(base, "after")
	s := strings.Repeat("x", maxLine+10) + "\n" + event(p, `"read"`) + "bad\n"
	got := collect(t, c, s)
	if !got.Incomplete || got.Counts.Lines != 3 || len(got.Profile.Files) != 1 || got.Counts.Dropped != 1 {
		t.Fatalf("%+v", got)
	}
	c2, _ := testCollector(t)
	if !c2.Snapshot().Incomplete {
		t.Fatal("live candidate marked complete")
	}
	if err := c2.Drain(failingReader{}); err == nil {
		t.Fatal("missing read error")
	}
	c2.Finish(errors.New("exit"))
	got = c2.Snapshot()
	if !strings.Contains(strings.Join(got.Reasons, ","), "log-read-error") || !strings.Contains(strings.Join(got.Reasons, ","), "abnormal-exit") {
		t.Fatal(got.Reasons)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("secret error must not escape") }

func TestCapacityAndPublicDial(t *testing.T) {
	c, base := testCollector(t)
	if err := c.OnPublicDial("Example.COM.", 443, "tcp"); err != nil {
		t.Fatal(err)
	}
	_ = c.OnPublicDial("example.com", 443, "tcp")
	_ = c.OnPublicDial("x.sydguard.internal", 443, "tcp")
	if c.OnPublicDial("127.0.0.1", 443, "tcp") == nil || c.OnPublicDial("example.com", 443, "udp") == nil {
		t.Fatal("accepted invalid dial")
	}
	var b strings.Builder
	for i := 0; i < maxEntries+50; i++ {
		b.WriteString(event(filepath.Join(base, fmt.Sprintf("f%d", i)), `"read"`))
	}
	b.WriteString(event(filepath.Join(base, "last"), `"write"`))
	got := collect(t, c, b.String())
	if !got.Incomplete || got.Counts.Lines != maxEntries+51 || got.Counts.Dropped == 0 || len(got.Profile.Network) != 1 || got.Profile.Network[0].Host != "example.com" {
		t.Fatalf("counts %+v", got.Counts)
	}
	if err := config.ValidateProfile("test", got.Profile); err != nil {
		t.Fatal(err)
	}
}

func TestMalformedStreamNeverPersistsUnexpectedFields(t *testing.T) {
	for i, input := range []string{`null`, `[]`, `{"ctx":"access","act":"warn","path":"/","cap":"read"}`, `{"ctx":"access","act":"warn","path":"/ok","cap":null}`, `{"ctx":"access","act":"warn","path":"/ok","cap":[7]}`, `{"ctx":"access","act":"warn","path":"/ok","cap":"read"} {}`} {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			c, _ := testCollector(t)
			got := collect(t, c, input+"\n")
			if len(got.Profile.Files) != 0 || !got.Incomplete {
				t.Fatalf("%+v", got)
			}
		})
	}
}

func TestRateLimitAndFinish(t *testing.T) {
	base := t.TempDir()
	c, err := New(Policy{Name: "test", Temporary: filepath.Join(base, "runtime"), PolicyDirectory: filepath.Join(base, "policy")})
	if err != nil {
		t.Fatal(err)
	}
	got := collect(t, c, "")
	if !got.Incomplete || got.Reasons[0] != "rate-limit-not-disabled" {
		t.Fatal(got.Reasons)
	}
}

func TestCapabilityGroups(t *testing.T) {
	for _, tt := range []struct{ capability, group string }{
		{"read", "read"},
		{"stat", "read"},
		{"readdir", "read"},
		{"chdir", "read"},
		{"readlink", "read"},
		{"write", "write"},
		{"create", "write"},
		{"truncate", "write"},
		{"chmod", "write"},
		{"chattr", "write"},
		{"mkdir", "write"},
		{"symlink", "write"},
		{"delete", "delete"},
		{"rmdir", "delete"},
		{"rename", "delete"},
	} {
		t.Run(tt.capability, func(t *testing.T) {
			c, base := testCollector(t)
			got := collect(t, c, event(filepath.Join(base, "entry"), fmt.Sprintf("%q", tt.capability)))
			if got.Incomplete || len(got.Profile.Files) != 1 || !reflect.DeepEqual(got.Profile.Files[0].Access, []string{tt.group}) {
				t.Fatalf("%+v", got)
			}
		})
	}
}

func TestDanglingProtectedSymlinkAndExcludedAncestor(t *testing.T) {
	c, base := testCollector(t)
	link := filepath.Join(base, "link")
	if err := os.Symlink(filepath.Join(base, ".env"), link); err != nil {
		t.Fatal(err)
	}
	got := collect(t, c, event(link, `"read"`)+event(base, `"delete"`))
	if len(got.Profile.Files) != 0 || !got.Incomplete {
		t.Fatalf("%+v", got)
	}
}

func FuzzMalformedLogNeverEscapesSchema(f *testing.F) {
	f.Add([]byte(`{"ctx":"access","act":"warn","path":"/safe","cap":["write","create"]}`))
	f.Add([]byte(`{"ctx":"access","act":"warn","path":"/safe","cap":"read","cmd":"SECRET"}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > maxLine {
			t.Skip()
		}
		c, err := New(Policy{Name: "fuzz", Temporary: "/tmp/sydguard-fuzz", PolicyDirectory: "/tmp/sydguard-policy", RateLimitDisabled: true})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Drain(strings.NewReader(string(input) + "\n")); err != nil {
			t.Fatal(err)
		}
		c.FinishOutcome(Outcome{})
		p := c.Snapshot().Profile
		if err := config.ValidateProfile("fuzz", p); err != nil {
			t.Fatalf("invalid output: %v", err)
		}
		for _, rule := range p.Files {
			if !safePath(rule.Path) || rule.Recursive {
				t.Fatal("nonliteral rule")
			}
		}
	})
}
