//go:build linux

package managedstore

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Gobd/syd-guard/internal/config"
	"golang.org/x/sys/unix"
)

func TestDecodeRequest(t *testing.T) {
	for _, data := range []string{`{"operation":"read","unknown":1}`, `{} {}`, strings.Repeat("x", 2*Limit+8193)} {
		if _, err := DecodeRequest(strings.NewReader(data)); err == nil {
			t.Fatalf("accepted invalid request (%d bytes)", len(data))
		}
	}
	r, err := DecodeRequest(strings.NewReader(`{"operation":"read","project":"id","name":"test","credential":"secret"}`))
	if err != nil || r.Operation != "read" {
		t.Fatalf("valid request: %v", err)
	}
	data, err := json.Marshal(Response{Error: "rejected"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("secret")) {
		t.Fatal("response leaked credential")
	}
}

func TestRegistrationUIDKeyBinding(t *testing.T) {
	a := (&Store{uid: 1001}).key(strings.Repeat("a", 64))
	b := (&Store{uid: 1002}).key(strings.Repeat("a", 64))
	if a == b {
		t.Fatal("distinct UIDs share registry key")
	}
	if a != (&Store{uid: 1001}).key(strings.Repeat("a", 64)) {
		t.Fatal("unstable registry key")
	}
}

// This tests detection, not atomic namespace binding: a rename can occur after
// any recheck, so the consumer must use the returned snapshot and Syd must pin
// the workload namespace independently.
func TestRegistrationIdentityAndSnapshotConsumption(t *testing.T) {
	project := t.TempDir()
	policy := filepath.Join(project, ".sydguard")
	if err := os.Mkdir(policy, 0o700); err != nil {
		t.Fatal(err)
	}
	var p, d unix.Stat_t
	if err := unix.Stat(project, &p); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat(policy, &d); err != nil {
		t.Fatal(err)
	}
	reg := registration{Project: project, ProjectDev: p.Dev, ProjectIno: p.Ino, PolicyDev: d.Dev, PolicyIno: d.Ino}
	if err := checkRegistrationIdentity(reg); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"version":1,"name":"test","files":[{"path":"src","access":["read"],"recursive":false}],"network":[]}`)
	snap, err := config.ParseManagedProfileSnapshot("test", payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(policy, filepath.Join(project, "detached")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(policy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := checkRegistrationIdentity(reg); err == nil {
		t.Fatal("replacement not detected")
	}
	if err := os.WriteFile(filepath.Join(policy, "test.json"), []byte("attacker"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(snap.Bytes(), payload) {
		t.Fatal("snapshot changed after namespace replacement")
	}
}
