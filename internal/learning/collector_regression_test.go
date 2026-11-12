package learning

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"
)

func TestRecordSchemaRejectsWholeEvent(t *testing.T) {
	cases := []struct{ name, input string }{
		{"null-context", `{"ctx":null,"act":"warn"}`},
		{"missing-context", `{"act":"warn"}`},
		{"unknown-context", `{"ctx":"other","act":"warn"}`},
		{"context-case", `{"Ctx":"access","act":"warn"}`},
		{"null-action", `{"ctx":"access","act":null}`},
		{"missing-action", `{"ctx":"access"}`},
		{"unknown-action", `{"ctx":"access","act":"future"}`},
		{"action-case", `{"ctx":"access","Act":"warn"}`},
		{"duplicate-case", `{"ctx":"access","CTX":"access","act":"warn"}`},
		{"nested-duplicate", `{"ctx":"access","act":"allow","extra":{"a":1,"a":2}}`},
		{"nested-case-duplicate", `{"ctx":"access","act":"allow","extra":{"a":1,"A":2}}`},
		{"null-version", `{"ctx":"access","act":"deny","version":null}`},
		{"deny-null-cap", `{"ctx":"access","act":"deny","cap":null}`},
		{"deny-missing-cap", `{"ctx":"access","act":"deny"}`},
		{"deny-null-path", `{"ctx":"access","act":"deny","cap":"read","path":null}`},
		{"null-path", `{"ctx":"access","act":"warn","path":null,"cap":"write"}`},
		{"null-cap", `{"ctx":"access","act":"warn","path":%q,"cap":null}`},
		{"mixed-unknown", `{"ctx":"access","act":"warn","path":%q,"cap":["write","SECRET_UNKNOWN"]}`},
		{"mixed-null", `{"ctx":"access","act":"warn","path":%q,"cap":["write",null]}`},
		{"mixed-number", `{"ctx":"access","act":"warn","path":%q,"cap":["write",3]}`},
		{"invalid-utf8", "{\"ctx\":\"access\",\"act\":\"warn\",\"cmd\":\"\xff\"}"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c, base := testCollector(t)
			line := tt.input
			if strings.Contains(line, "%q") {
				line = fmt.Sprintf(line, filepath.Join(base, "target"))
			}
			got := collect(t, c, line+"\n")
			if !got.Incomplete || got.Counts.Rejected != 1 || len(got.Profile.Files) != 0 {
				t.Fatalf("%+v", got)
			}
			encoded, err := json.Marshal(got)
			if err != nil || strings.Contains(string(encoded), "SECRET_UNKNOWN") {
				t.Fatalf("raw field leaked: %s %v", encoded, err)
			}
		})
	}
}

func TestWarnNullErrorIsOnlyPermissionCheck(t *testing.T) {
	c, base := testCollector(t)
	line := fmt.Sprintf(`{"ctx":"access","act":"warn","path":%q,"cap":"write","err":null}`+"\n", filepath.Join(base, "target"))
	got := collect(t, c, line)
	if got.Incomplete || got.Kind != "permission-check-candidate" || len(got.Profile.Files) != 1 || len(got.Profile.Files[0].Access) != 1 || got.Profile.Files[0].Access[0] != "write" {
		t.Fatalf("%+v", got)
	}
}

func TestExplicitKnownNonWarnRecords(t *testing.T) {
	c, _ := testCollector(t)
	got := collect(t, c, "{\"ctx\":\"access\",\"act\":\"allow\",\"cap\":\"read\"}\n{\"ctx\":\"access\",\"act\":\"deny\",\"cap\":\"net/connect\",\"version\":1}\n")
	if got.Incomplete || got.Counts.Rejected != 0 || len(got.Profile.Files) != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestFinishOutcomeReportsFailuresWithoutRawValues(t *testing.T) {
	for _, tt := range []struct {
		name    string
		outcome Outcome
		reason  string
	}{
		{"nonzero", Outcome{ExitCode: 1}, "abnormal-exit"},
		{"launch-error", Outcome{Err: errors.New("SECRET")}, "abnormal-exit"},
		{"signal", Outcome{Signal: syscall.SIGTERM}, "abnormal-exit"},
		{"cancelled", Outcome{Cancelled: true}, "abnormal-exit"},
		{"scanner", Outcome{ScannerError: errors.New("SECRET")}, "scanner-error"},
		{"delivery", Outcome{DeliveryError: errors.New("SECRET")}, "delivery-error"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := testCollector(t)
			if err := c.Drain(strings.NewReader("")); err != nil {
				t.Fatal(err)
			}
			c.FinishOutcome(tt.outcome)
			got := c.Snapshot()
			b, _ := json.Marshal(got)
			if !got.Incomplete || !strings.Contains(strings.Join(got.Reasons, ","), tt.reason) || strings.Contains(string(b), "SECRET") {
				t.Fatalf("%s", b)
			}
		})
	}
	c, _ := testCollector(t)
	_ = c.Drain(strings.NewReader(""))
	c.Finish(nil)
	if got := c.Snapshot(); !got.Incomplete || !strings.Contains(strings.Join(got.Reasons, ","), "workload-outcome-unknown") {
		t.Fatal(got)
	}
}

func TestStreamWaitsForDialsAndEOF(t *testing.T) {
	c, base := testCollector(t)
	r, w := io.Pipe()
	s, err := StartStream(c, r)
	if err != nil {
		t.Fatal(err)
	}
	callbackStarted, releaseCallback := make(chan struct{}), make(chan struct{})
	done := make(chan ProfileCandidate, 1)
	go func() {
		got, _ := s.Finish(Outcome{}, func() error {
			close(callbackStarted)
			<-releaseCallback
			return c.OnPublicDial("example.com", 443, "tcp")
		})
		done <- got
	}()
	<-callbackStarted
	select {
	case <-done:
		t.Fatal("did not await dial callbacks")
	default:
	}
	close(releaseCallback)
	if _, err := io.WriteString(w, event(filepath.Join(base, "x"), `"read"`)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		t.Fatal("did not await EOF")
	default:
	}
	_ = w.Close()
	select {
	case got := <-done:
		if got.Incomplete || len(got.Profile.Network) != 1 || len(got.Profile.Files) != 1 {
			t.Fatalf("%+v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("finish blocked after EOF")
	}
	if err := c.OnPublicDial("example.com", 443, "tcp"); err == nil || !c.Snapshot().Incomplete {
		t.Fatal("late callback not recorded")
	}
}

func TestStreamDeliveryFailure(t *testing.T) {
	for _, callback := range []func() error{nil, func() error { return errors.New("SECRET") }} {
		c, _ := testCollector(t)
		s, err := StartStream(c, failingReader{})
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.Finish(Outcome{}, callback)
		if err == nil || !got.Incomplete || !strings.Contains(strings.Join(got.Reasons, ","), "delivery-error") || !strings.Contains(strings.Join(got.Reasons, ","), "log-read-error") {
			t.Fatal(got, err)
		}
		b, _ := json.Marshal(got)
		if strings.Contains(string(b), "SECRET") {
			t.Fatal(string(b))
		}
	}
}

func TestRuntimeExclusionReresolved(t *testing.T) {
	base := t.TempDir()
	a, b := filepath.Join(base, "a"), filepath.Join(base, "b")
	for _, p := range []string{a, b} {
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(base, "runtime-link")
	if err := os.Symlink(a, link); err != nil {
		t.Fatal(err)
	}
	c, err := New(Policy{Name: "test", Temporary: link, PolicyDirectory: filepath.Join(base, "policy"), RateLimitDisabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(b, link); err != nil {
		t.Fatal(err)
	}
	got := collect(t, c, event(filepath.Join(b, "secret"), `"read"`)+event(filepath.Join(a, "secret"), `"read"`))
	if got.Incomplete || len(got.Profile.Files) != 0 {
		t.Fatal(got)
	}
}

func TestPublicDialContractValidation(t *testing.T) {
	c, _ := testCollector(t)
	for _, host := range []string{"127.0.0.1", "10.0.0.1", "::1", "bad host", "localhost", ""} {
		if err := c.OnPublicDial(host, 443, "tcp"); err == nil {
			t.Fatalf("accepted %q", host)
		}
	}
	if err := c.OnPublicDial("example.com", 443, "udp"); err == nil {
		t.Fatal("accepted UDP")
	}
	if err := c.OnPublicDial("db.sydguard.internal", 443, "tcp"); err != nil {
		t.Fatal(err)
	}
	got := collect(t, c, "")
	if len(got.Profile.Network) != 0 || !got.Incomplete {
		t.Fatal(got)
	}
}

func TestPublicDialLimitAndSnapshotIsolation(t *testing.T) {
	c, _ := testCollector(t)
	accepted := 0
	for i := 0; i <= maxEntries; i++ {
		if err := c.OnPublicDial(fmt.Sprintf("h%d.example.com", i), 443, "tcp"); err != nil {
			break
		}
		accepted++
	}
	got := collect(t, c, "")
	if accepted == 0 || !got.Incomplete || got.Counts.Dropped != 1 || len(got.Profile.Network) != accepted {
		t.Fatal(got.Counts)
	}
	got.Profile.Network[0].Host = "modified.example.com"
	got.Reasons[0] = "modified"
	fresh := c.Snapshot()
	if fresh.Profile.Network[0].Host == "modified.example.com" || fresh.Reasons[0] == "modified" {
		t.Fatal("snapshot aliases collector")
	}
}

func FuzzCapabilityArrayRejectsUnknownWholeEvent(f *testing.F) {
	f.Add("new-cap")
	f.Add("SECRET")
	f.Fuzz(func(t *testing.T, unknown string) {
		if len(unknown) > 256 || !utf8.ValidString(unknown) {
			t.Skip()
		}
		for _, known := range []string{"read", "stat", "readdir", "chdir", "readlink", "write", "create", "truncate", "chmod", "chattr", "mkdir", "symlink", "delete", "rmdir", "rename"} {
			if unknown == known {
				t.Skip()
			}
		}
		c, base := testCollector(t)
		caps, _ := json.Marshal([]string{"write", unknown})
		got := collect(t, c, event(filepath.Join(base, "target"), string(caps)))
		if !got.Incomplete || len(got.Profile.Files) != 0 {
			t.Fatalf("partially accepted event: %+v", got)
		}
	})
}
