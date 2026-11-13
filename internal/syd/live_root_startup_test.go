package syd

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestRootWriterStartupTypedAndBankBaseline(t *testing.T) {
	dir, err := os.MkdirTemp("", "sgroot-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(root, "project")
	tmp := filepath.Join(root, "tmp")
	for _, p := range []string{work, tmp} {
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	gate := filepath.Join(root, "gate")
	if err := os.WriteFile(gate, []byte("fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(gate)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	spec := RootWriterStartup{GatePath: gate, GateDev: uint64(st.Dev), GateIno: uint64(st.Ino), UID: 502, GID: 1000, ReleaseFD: 3, WholeProjectRWD: true, RequirePIE: true}
	binding := BankBinding{Session: strings.Repeat("a", 64), Project: strings.Repeat("b", 64), Profile: "build", Generation: 1}
	l, profile, err := NewRootWriterBankLedger(binding, liveBankEngineSHA256, work, tmp, filepath.Join(root, "s"), []string{filepath.Join(root, "authority")}, spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ipc/uid:0\nipc/gid:0\npassfd^\npassfd+stdio,3\n", "allow/read,stat,exec+" + gate + "\n", "allow/lock/read,exec+" + gate + "\n", "allow/lock/read,readdir,write,create,delete,rename,truncate,mkdir,rmdir,symlink+" + work + "\n", "trace/allow_unsafe_exec_nopie:0\n"} {
		if !strings.Contains(profile, want) {
			t.Errorf("missing startup %q", want)
		}
	}
	if strings.Contains(profile, "passfd+all") || strings.Contains(profile, "allow/lock/read,readdir,write,create,delete,rename,truncate,mkdir,rmdir,symlink,exec+"+work) {
		t.Fatal("startup widened gate or project execution")
	}
	_, normal, err := NewBankLedger(binding, liveBankEngineSHA256, work, tmp, filepath.Join(root, "s"), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(normal, "ipc/uid:0") || strings.Contains(normal, "ipc/gid:0") || strings.Contains(normal, "passfd+stdio,3") {
		t.Fatal("ordinary bank startup changed")
	}
	if strings.Index(profile, "ipc/uid:0") > strings.Index(profile, "domain+@sgbankA") || len(l.StartupFingerprint()) != 64 {
		t.Fatal("bad immutable startup")
	}
	intent := []byte(`{"version":1,"name":"build","files":[],"network":[]}`)
	batch, err := l.Prepare(l.InitialReceipt(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(batch.Bytes()), "ipc/uid:") || strings.Contains(string(batch.Bytes()), "passfd") || strings.Contains(string(batch.Bytes()), "allow/lock/") {
		t.Fatal("startup configuration in dynamic batch")
	}
	if err := l.Finish(batch.Receipt, true); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "data"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	readIntent := []byte(`{"version":1,"name":"build","files":[{"path":"data","access":["read"],"recursive":false}],"network":[]}`)
	second, err := l.Prepare(batch.Receipt, readIntent)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(second.Bytes()), "ipc/uid:") || strings.Contains(string(second.Bytes()), "passfd") || !strings.Contains(string(second.Bytes()), "allow/read") {
		t.Fatal("dynamic update violated root startup baseline")
	}
	if err := l.Finish(second.Receipt, true); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*RootWriterStartup){func(s *RootWriterStartup) { s.UID++ }, func(s *RootWriterStartup) { s.GID++ }, func(s *RootWriterStartup) { s.RequirePIE = false }} {
		different := spec
		change(&different)
		l2, _, err := NewRootWriterBankLedger(binding, liveBankEngineSHA256, work, tmp, filepath.Join(root, "s"), []string{filepath.Join(root, "authority")}, different)
		if err != nil {
			t.Fatal(err)
		}
		if l.StartupFingerprint() == l2.StartupFingerprint() {
			t.Fatal("startup identity not fingerprinted")
		}
	}
	changedProtected, _, err := NewRootWriterBankLedger(binding, liveBankEngineSHA256, work, tmp, filepath.Join(root, "s"), []string{filepath.Join(root, "other-authority")}, spec)
	if err != nil {
		t.Fatal(err)
	}
	if changedProtected.StartupFingerprint() == l.StartupFingerprint() {
		t.Fatal("protected authority not fingerprinted")
	}
	if _, _, err := NewRootWriterBankLedger(binding, strings.Repeat("0", 64), work, tmp, filepath.Join(root, "s"), nil, spec); err == nil {
		t.Fatal("wrong engine identity accepted")
	}
	if _, _, err := NewRootWriterBankLedger(binding, liveBankEngineSHA256, work, tmp, filepath.Join(root, "s"), []string{root}, spec); err == nil {
		t.Fatal("gate under protected authority accepted")
	}
	for _, bad := range []RootWriterStartup{func() RootWriterStartup { x := spec; x.WholeProjectRWD = false; return x }(), func() RootWriterStartup { x := spec; x.GateIno++; return x }(), func() RootWriterStartup { x := spec; x.ReleaseFD = 2; return x }(), func() RootWriterStartup { x := spec; x.ReleaseFD++; return x }()} {
		if _, _, err := NewRootWriterBankLedger(binding, liveBankEngineSHA256, work, tmp, filepath.Join(root, "s"), nil, bad); err == nil {
			t.Fatal("invalid root startup accepted")
		}
	}
}

func TestRootWriterStartupRejectsCanonicalGateOverlap(t *testing.T) {
	dir, err := os.MkdirTemp("", "sgalias-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	work, tmp := filepath.Join(root, "project"), filepath.Join(root, "scratch")
	for _, p := range []string{work, tmp} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	binding := BankBinding{Session: strings.Repeat("a", 64), Project: strings.Repeat("b", 64), Profile: "build", Generation: 1}
	for _, inside := range []string{work, tmp} {
		t.Run(filepath.Base(inside), func(t *testing.T) {
			gate := filepath.Join(inside, "gate")
			if err := os.WriteFile(gate, []byte("fixture"), 0700); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(gate)
			if err != nil {
				t.Fatal(err)
			}
			st := info.Sys().(*syscall.Stat_t)
			alias := filepath.Join(root, filepath.Base(inside)+"-alias")
			if err := os.Symlink(inside, alias); err != nil {
				t.Fatal(err)
			}
			w, temp := work, tmp
			if inside == work {
				w = alias
			} else {
				temp = alias
			}
			spec := RootWriterStartup{GatePath: gate, GateDev: uint64(st.Dev), GateIno: uint64(st.Ino), UID: 502, GID: 1000, ReleaseFD: FixedReleaseFD, WholeProjectRWD: true}
			ledger, profile, err := NewRootWriterBankLedger(binding, liveBankEngineSHA256, w, temp, filepath.Join(root, "socket"), nil, spec)
			if err == nil || ledger != nil || profile != "" {
				t.Fatal("gate inside canonical project/scratch compiled")
			}
		})
	}
}
