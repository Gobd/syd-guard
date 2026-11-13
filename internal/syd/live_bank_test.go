package syd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func bankFixture(t *testing.T, pie bool) (*BankLedger, string) {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "syd-bank-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(root, "project")
	temp := filepath.Join(root, "temp")
	for _, p := range []string{work, temp} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	binding := BankBinding{Session: strings.Repeat("a", 64), Project: strings.Repeat("b", 64), Profile: "build", Generation: 1}
	l, start, err := NewBankLedger(binding, liveBankEngineSHA256, work, temp, filepath.Join(root, "ipc.sock"), []string{filepath.Join(root, "authority")}, pie)
	if err != nil {
		t.Fatal(err)
	}
	return l, start
}

func bankIntent(path, access string) []byte {
	return []byte(fmt.Sprintf(`{"version":1,"name":"build","files":[{"path":%q,"access":[%q],"recursive":false}],"network":[]}`, path, access))
}

func TestLiveBankStartupAndPrefixSafety(t *testing.T) {
	l, start := bankFixture(t, false)
	for _, s := range []string{"trace/allow_unsafe_exec_nopie:1\n", "sandbox/chdir:on\n", "sandbox/readlink:on\n", "domain+@sgbankA:@default\n", "domain+@sgbankB:@default\n", "lock:ipc\n"} {
		if !strings.Contains(start, s) {
			t.Fatalf("missing %s", s)
		}
	}
	for _, category := range []string{"sandbox/chdir:on\n", "sandbox/readlink:on\n"} {
		if strings.Count(start, category) != 1 || strings.Index(start, category) > strings.Index(start, "domain+@sgbankA:@default\n") || strings.Index(start, category) > strings.Index(start, "domain+@sgbankB:@default\n") {
			t.Fatalf("required category not enabled before clones: %s", category)
		}
	}
	if !strings.Contains(start, "deny/all+"+l.protected[len(l.protected)-1]+"\n") || !strings.Contains(start, "deny/all+/.env\n") {
		t.Fatal("startup missing protected all-capability denies")
	}
	if strings.Contains(start, "cmd/move!") || strings.Contains(start, "move/@") {
		t.Fatal("automatic or startup move")
	}
	_, pie := bankFixture(t, true)
	if !strings.Contains(pie, "trace/allow_unsafe_exec_nopie:0\n") {
		t.Fatal("missing PIE opt-in")
	}
	r := l.InitialReceipt()
	for _, path := range []string{"first", "second", "third", "fourth"} {
		b, err := l.Prepare(r, bankIntent(path, "read"))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(string(b.Bytes()), "\n"), "\n")
		bank := "sgbankA"
		if r.Sequence%2 == 1 {
			bank = "sgbankB"
		}
		if lines[0] != "cmd/move!default" || lines[len(lines)-1] != "cmd/move!"+bank {
			t.Fatalf("bad boundaries: %q / %q", lines[0], lines[len(lines)-1])
		}
		// At every possible failed prefix, either the original complete bank remains
		// selected (zero commands), or the restrictive default is selected. Only the
		// final command publishes the fully rebuilt target.
		selected := "old"
		for i, line := range lines {
			if strings.HasPrefix(line, "cmd/move!") {
				if i == 0 {
					selected = "default"
				} else if i == len(lines)-1 {
					selected = bank
				} else {
					t.Fatal("intermediate move")
				}
			} else if selected != "default" {
				t.Fatalf("mutation while %s selected", selected)
			}
			if i < len(lines)-1 && selected != "default" {
				t.Fatalf("unsafe prefix %d", i+1)
			}
		}
		tailStart := len(lines) - 1 - len(l.tail)
		for i, line := range l.tail {
			if lines[tailStart+i] != "@"+bank+"/"+line {
				t.Fatalf("protected tail out of order")
			}
		}
		if r.Sequence >= 2 {
			old := []string{"first", "second"}[r.Sequence%2]
			if !strings.Contains(string(b.Bytes()), "^"+filepath.Join(l.workdir, old)+"\n") {
				t.Fatalf("missing obsolete grant removal for %s", old)
			}
		}
		data := b.Bytes()
		data[0] = 'X'
		if b.Bytes()[0] == 'X' {
			t.Fatal("batch bytes exposed")
		}
		if err := l.Finish(b.Receipt, true); err != nil {
			t.Fatal(err)
		}
		r = b.Receipt
	}
}

func TestLiveBankStaleUnknownAndBounds(t *testing.T) {
	l, _ := bankFixture(t, false)
	initial := l.InitialReceipt()
	bad := []string{
		`{"version":1,"name":"build","files":[{"path":"../x","access":["read"],"recursive":false}],"network":[]}`,
		`{"version":1,"name":"build","files":[{"path":"x*","access":["read"],"recursive":false}],"network":[]}`,
		`{"version":1,"name":"build","files":[{"path":"x","access":["exec"],"recursive":false}],"network":[]}`,
		`{"version":1,"name":"build","files":[{"path":"x","access":["read","read"],"recursive":false}],"network":[]}`,
		`{"version":1,"name":"build","files":[],"network":[{"host":"example.com","port":443,"transport":"tcp"}]}`,
		strings.Repeat("x", liveBankMaxBytes+1),
	}
	for _, v := range bad {
		if _, err := l.Prepare(initial, []byte(v)); err == nil {
			t.Fatalf("accepted invalid: %.80s", v)
		}
	}
	var files []string
	for i := 0; i < liveBankMaxRules+1; i++ {
		files = append(files, fmt.Sprintf(`{"path":"x%d","access":["read"],"recursive":false}`, i))
	}
	oversized := `{"version":1,"name":"build","files":[` + strings.Join(files, ",") + `],"network":[]}`
	if _, err := l.Prepare(initial, []byte(oversized)); err == nil {
		t.Fatal("accepted too many rules")
	}
	b, err := l.Prepare(initial, bankIntent("x", "write"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = l.Prepare(initial, bankIntent("y", "read")); err == nil {
		t.Fatal("accepted concurrent update")
	}
	stale := b.Receipt
	stale.Sequence++
	if err = l.Finish(stale, true); err == nil {
		t.Fatal("accepted unknown receipt")
	}
	if err = l.Finish(b.Receipt, true); err == nil {
		t.Fatal("accepted correct ACK after unknown receipt")
	}
	if l.pending != nil || !l.stopped {
		t.Fatal("unknown receipt did not clear pending and quarantine")
	}
	if _, err = l.Prepare(initial, bankIntent("x", "write")); err == nil {
		t.Fatal("accepted prepare after unknown receipt")
	}
	// Exercise acknowledged ABA and uncertain outcomes in a fresh ledger.
	l, _ = bankFixture(t, false)
	initial = l.InitialReceipt()
	b, err = l.Prepare(initial, bankIntent("x", "write"))
	if err != nil {
		t.Fatal(err)
	}
	if err = l.Finish(b.Receipt, true); err != nil {
		t.Fatal(err)
	}
	if _, err = l.Prepare(initial, bankIntent("x", "write")); err == nil {
		t.Fatal("accepted ABA predecessor")
	}
	b2, err := l.Prepare(b.Receipt, bankIntent("x", "write"))
	if err != nil {
		t.Fatal(err)
	}
	if b2.Receipt.Revision != b.Receipt.Revision || b2.Receipt.Sequence == b.Receipt.Sequence {
		t.Fatal("ABA sequence not bound")
	}
	if err = l.Finish(b2.Receipt, false); err == nil {
		t.Fatal("accepted uncertain outcome")
	}
	if _, err = l.Prepare(b.Receipt, bankIntent("z", "read")); err == nil {
		t.Fatal("reused quarantined banks")
	}
	if err = l.Finish(b2.Receipt, true); err == nil {
		t.Fatal("accepted late ACK")
	}
}

func TestLiveBankIdentityAndSerialization(t *testing.T) {
	l, _ := bankFixture(t, false)
	socket := filepath.Join(filepath.Dir(l.workdir), "gate.sock")
	if _, _, err := NewBankLedger(l.binding, liveBankEngineSHA256, l.workdir, l.temporary, socket, nil, false); err != nil {
		t.Fatalf("valid candidate identity rejected: %v", err)
	}
	if _, _, err := NewBankLedger(l.binding, "3.59.0", l.workdir, l.temporary, socket, nil, false); err == nil {
		t.Fatal("accepted stock version")
	}
	if _, _, err := NewBankLedger(l.binding, strings.Repeat("0", 64), l.workdir, l.temporary, socket, nil, false); err == nil {
		t.Fatal("accepted unknown digest")
	}
	for _, socket := range []string{filepath.Join(l.workdir, "sock"), filepath.Join(l.temporary, "sock")} {
		if _, _, err := NewBankLedger(l.binding, liveBankEngineSHA256, l.workdir, l.temporary, socket, nil, false); err == nil {
			t.Fatal("accepted workload-reachable socket path")
		}
	}
	if bankLinesValid([]string{strings.Repeat("x", 4096)}) || bankLinesValid([]string{"\xff"}) {
		t.Fatal("accepted invalid line")
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := l.Prepare(l.InitialReceipt(), bankIntent("x", "read")); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("%d simultaneous prepares succeeded", successes)
	}
}

func TestLiveBankEveryFailurePrefixQuarantined(t *testing.T) {
	l, _ := bankFixture(t, false)
	intent := bankIntent("project-file", "delete")
	batch, err := l.Prepare(l.InitialReceipt(), intent)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(batch.Bytes()), "\n"), "\n")
	// Simulate failure before the first command, after each command, and even
	// after final activation with a lost ACK. No outcome is treated as rollback.
	for prefix := 0; prefix <= len(lines); prefix++ {
		t.Run(fmt.Sprint(prefix), func(t *testing.T) {
			ledger, _ := bankFixture(t, false)
			b, err := ledger.Prepare(ledger.InitialReceipt(), intent)
			if err != nil {
				t.Fatal(err)
			}
			commands := strings.Split(strings.TrimSuffix(string(b.Bytes()), "\n"), "\n")
			if len(commands) != len(lines) {
				t.Fatal("fixture changed emitted prefix count")
			}
			var inactive bankACLModel
			for _, line := range append(append([]string(nil), ledger.base...), ledger.tail...) {
				if (strings.HasPrefix(line, "allow/") || strings.HasPrefix(line, "deny/")) && strings.Contains(line, "+") && !strings.HasPrefix(line, "allow/lock/") {
					inactive.apply(t, line)
				}
			}
			selected := "default"
			for i, line := range commands[:prefix] {
				switch {
				case line == "cmd/move!default" && i == 0:
					selected = "default"
				case line == "cmd/move!sgbankA" && i == len(commands)-1:
					selected = "sgbankA"
				case strings.HasPrefix(line, "@sgbankA/") && selected == "default":
					inactive.apply(t, strings.TrimPrefix(line, "@sgbankA/"))
				default:
					t.Fatalf("unsafe modeled prefix command %d: %s", i, line)
				}
			}
			if prefix < len(commands) && selected != "default" || prefix == len(commands) && selected != "sgbankA" {
				t.Fatal("incorrect selected domain at failure boundary")
			}
			if err := ledger.Finish(b.Receipt, false); err == nil {
				t.Fatal("accepted failure")
			}
			if _, err := ledger.Prepare(ledger.InitialReceipt(), intent); err == nil {
				t.Fatal("reused failed bank")
			}
		})
	}
}

func TestLiveBankProtectedAndLiteralResolution(t *testing.T) {
	l, _ := bankFixture(t, false)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(l.workdir, "escape")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"escape/file", "../outside", "/etc/passwd", "a\ncmd/move!sgbankA", "a$HOME", "a;bad", "a?bad", strings.Repeat("x", 4096)} {
		if _, err := l.Prepare(l.InitialReceipt(), bankIntent(path, "read")); err == nil {
			t.Errorf("accepted %q", path)
		}
	}
	// Every bank retains the immutable policy and protected-authority tail.
	b, err := l.Prepare(l.InitialReceipt(), bankIntent(".env", "read"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(b.Bytes()), "\n"), "\n")
	start := len(lines) - 1 - len(l.tail)
	for i, deny := range l.tail {
		if lines[start+i] != "@sgbankA/"+deny {
			t.Fatal("protected deny not last")
		}
	}
}

func TestLiveBankSocketByteBoundary(t *testing.T) {
	l, _ := bankFixture(t, false)
	root := filepath.Dir(l.workdir)
	prefix := root + string(filepath.Separator)
	// Include a multibyte character to ensure the limit is bytes, not runes.
	for _, size := range []int{107, 108} {
		padding := size - len(prefix) - len("é")
		if padding < 1 {
			t.Fatalf("fixture root too long: %d", len(prefix))
		}
		socket := prefix + "é" + strings.Repeat("x", padding)
		if len(socket) != size {
			t.Fatal("invalid boundary fixture")
		}
		_, startup, err := NewBankLedger(l.binding, liveBankEngineSHA256, l.workdir, l.temporary, socket, nil, false)
		if size == 107 {
			if err != nil || !strings.Contains(startup, "ipc:"+socket+"\n") {
				t.Fatalf("107 bytes rejected: %v", err)
			}
		} else if err == nil {
			t.Fatal("108-byte socket accepted")
		}
	}
	if _, _, err := NewBankLedger(l.binding, liveBankEngineSHA256, l.workdir, l.temporary, prefix+"\xff", nil, false); err == nil {
		t.Fatal("invalid UTF-8 socket accepted")
	}
}

func TestLiveBankUnknownFinishQuarantines(t *testing.T) {
	mutations := map[string]func(*BankReceipt){
		"session":    func(r *BankReceipt) { r.Binding.Session = strings.Repeat("c", 64) },
		"project":    func(r *BankReceipt) { r.Binding.Project = strings.Repeat("c", 64) },
		"profile":    func(r *BankReceipt) { r.Binding.Profile = "other" },
		"generation": func(r *BankReceipt) { r.Binding.Generation++ },
		"sequence":   func(r *BankReceipt) { r.Sequence++ },
		"revision":   func(r *BankReceipt) { r.Revision = strings.Repeat("c", 64) },
	}
	for name, mutate := range mutations {
		for _, ack := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%v", name, ack), func(t *testing.T) {
				l, _ := bankFixture(t, false)
				b, err := l.Prepare(l.InitialReceipt(), bankIntent("x", "read"))
				if err != nil {
					t.Fatal(err)
				}
				unknown := b.Receipt
				mutate(&unknown)
				if err := l.Finish(unknown, ack); err == nil {
					t.Fatal("unknown finish accepted")
				}
				if !l.stopped || l.pending != nil {
					t.Fatal("ledger not quarantined")
				}
				if err := l.Finish(b.Receipt, true); err == nil {
					t.Fatal("late correct ACK accepted")
				}
				if _, err := l.Prepare(l.InitialReceipt(), bankIntent("y", "read")); err == nil {
					t.Fatal("prepare accepted after unknown finish")
				}
			})
		}
	}
	l, _ := bankFixture(t, false)
	if err := l.Finish(l.InitialReceipt(), true); err == nil {
		t.Fatal("finish without pending accepted")
	}
	if _, err := l.Prepare(l.InitialReceipt(), bankIntent("x", "read")); err == nil {
		t.Fatal("prepare after unsolicited finish accepted")
	}
}

func TestLiveBankReceiptBindingBytesAndExhaustion(t *testing.T) {
	l, _ := bankFixture(t, false)
	initial := l.InitialReceipt()
	for name, mutate := range map[string]func(*BankReceipt){
		"session":    func(r *BankReceipt) { r.Binding.Session = strings.Repeat("c", 64) },
		"project":    func(r *BankReceipt) { r.Binding.Project = strings.Repeat("c", 64) },
		"profile":    func(r *BankReceipt) { r.Binding.Profile = "other" },
		"generation": func(r *BankReceipt) { r.Binding.Generation++ },
		"sequence":   func(r *BankReceipt) { r.Sequence++ },
		"revision":   func(r *BankReceipt) { r.Revision = strings.Repeat("c", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := initial
			mutate(&bad)
			if _, err := l.Prepare(bad, bankIntent("x", "read")); err == nil {
				t.Fatal("mismatched binding accepted")
			}
		})
	}
	first := bankIntent("x", "read")
	b, err := l.Prepare(initial, first)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(first)
	if b.Receipt.Revision != hex.EncodeToString(hash[:]) {
		t.Fatal("revision is not exact submitted bytes")
	}
	if err := l.Finish(b.Receipt, true); err != nil {
		t.Fatal(err)
	}
	second := append([]byte(" \n"), first...)
	b2, err := l.Prepare(b.Receipt, second)
	if err != nil {
		t.Fatal(err)
	}
	hash = sha256.Sum256(second)
	if b2.Receipt.Revision != hex.EncodeToString(hash[:]) || b2.Receipt.Revision == b.Receipt.Revision {
		t.Fatal("revision ignored exact byte differences")
	}
	if err := l.Finish(b2.Receipt, true); err != nil {
		t.Fatal(err)
	}
	l.receipt.Sequence = ^uint64(0)
	if _, err := l.Prepare(l.receipt, first); err == nil || l.pending != nil {
		t.Fatal("sequence wrap accepted")
	}
}

// bankACLModel models only compiler-owned ACL entries and Syd's documented ^
// capability removal on an identical action/pattern, not engine enforcement.
type bankACLModelEntry struct {
	action, pattern string
	caps            map[string]bool
}

type bankACLModel []bankACLModelEntry

func (m *bankACLModel) apply(t *testing.T, command string) {
	t.Helper()
	i := strings.IndexAny(command, "+^")
	if i < 0 {
		t.Fatalf("invalid ACL command %q", command)
	}
	head, pattern, op := command[:i], command[i+1:], command[i]
	parts := strings.SplitN(head, "/", 2)
	if len(parts) != 2 {
		t.Fatalf("invalid ACL head %q", head)
	}
	caps := strings.Split(parts[1], ",")
	if op == '+' {
		entry := bankACLModelEntry{action: parts[0], pattern: pattern, caps: map[string]bool{}}
		for _, cap := range caps {
			entry.caps[cap] = true
		}
		*m = append(*m, entry)
		return
	}
	kept := (*m)[:0]
	for _, entry := range *m {
		if entry.action == parts[0] && entry.pattern == pattern {
			for _, cap := range caps {
				delete(entry.caps, cap)
			}
		}
		if len(entry.caps) > 0 {
			kept = append(kept, entry)
		}
	}
	*m = kept
}

func (m bankACLModel) count(action, pattern, cap string) int {
	n := 0
	for _, entry := range m {
		if entry.action == action && entry.pattern == pattern && entry.caps[cap] {
			n++
		}
	}
	return n
}

// decisionOnProjectEnv models just the concrete .env and project-prefix
// patterns used below; it is not a general Syd glob implementation.
func (m bankACLModel) decisionOnProjectEnv(project, cap string) string {
	decision := ""
	for _, entry := range m {
		matches := entry.pattern == project+"/***" || entry.pattern == "/**/.env"
		if matches && (entry.caps[cap] || entry.caps["all"]) {
			decision = entry.action
		}
	}
	return decision
}

func TestLiveBankOwnedInventoryReplacementModel(t *testing.T) {
	l, _ := bankFixture(t, false)
	var banks [2]bankACLModel
	for i := range banks {
		for _, line := range append(append([]string(nil), l.base...), l.tail...) {
			if (strings.HasPrefix(line, "allow/") || strings.HasPrefix(line, "deny/")) && strings.Contains(line, "+") && !strings.HasPrefix(line, "allow/lock/") {
				banks[i].apply(t, line)
			}
		}
	}
	intents := [][]byte{
		[]byte(`{"version":1,"name":"build","files":[{"path":".","access":["read","write","delete"],"recursive":true}],"network":[]}`),
		[]byte(`{"version":1,"name":"build","files":[],"network":[]}`),
		[]byte(`{"version":1,"name":"build","files":[{"path":".","access":["read"],"recursive":false}],"network":[]}`),
		[]byte(`{"version":1,"name":"build","files":[],"network":[]}`),
		[]byte(`{"version":1,"name":"build","files":[],"network":[]}`),
	}
	receipt := l.InitialReceipt()
	for step, intent := range intents {
		b, err := l.Prepare(receipt, intent)
		if err != nil {
			t.Fatal(err)
		}
		bank := step % 2
		name := []string{"sgbankA", "sgbankB"}[bank]
		lines := strings.Split(strings.TrimSuffix(string(b.Bytes()), "\n"), "\n")
		for _, line := range lines[1 : len(lines)-1] {
			prefix := "@" + name + "/"
			if !strings.HasPrefix(line, prefix) {
				t.Fatalf("non-owned rule %q", line)
			}
			banks[bank].apply(t, strings.TrimPrefix(line, prefix))
		}
		if err := l.Finish(b.Receipt, true); err != nil {
			t.Fatal(err)
		}
		receipt = b.Receipt
		if step == 0 && (banks[0].count("allow", l.workdir, "write") != 1 || banks[0].count("allow", l.workdir+"/***", "read") != 1) {
			t.Fatal("recursive read/write not installed")
		}
		if step == 0 {
			for _, cap := range []string{"chdir", "readlink"} {
				if banks[0].decisionOnProjectEnv(l.workdir, cap) != "deny" {
					t.Fatalf("protected .env %s did not override recursive allow", cap)
				}
			}
		}
		if step == 2 {
			for _, cap := range []string{"write", "create", "truncate", "chmod", "chattr", "mkdir", "symlink", "delete", "rmdir", "rename"} {
				if banks[0].count("allow", l.workdir, cap) != 0 || banks[0].count("allow", l.workdir+"/***", cap) != 0 {
					t.Fatalf("mutation capability %s survived access reduction", cap)
				}
			}
			if banks[0].count("allow", l.workdir+"/***", "read") != 0 || banks[0].count("allow", l.workdir, "read") != 1 {
				t.Fatal("recursive grant survived exact replacement")
			}
			if banks[0].count("allow", l.workdir, "chdir") != 2 {
				t.Fatal("baseline collision was not restored exactly once alongside new grant")
			}
		}
		if step == 4 {
			if banks[0].count("allow", l.workdir, "read") != 0 || banks[0].count("allow", l.workdir, "write") != 0 || banks[0].count("allow", l.workdir, "chdir") != 1 || banks[0].count("allow", l.workdir, "stat") != 1 {
				t.Fatal("empty replacement did not restore baseline only")
			}
		}
		// The immutable protected rules are the last ACLs in the model after
		// every completed rebuild, including the two lookup capabilities.
		model := banks[bank]
		if len(model) < len(l.tail) {
			t.Fatal("missing protected tail")
		}
		for i, deny := range l.tail {
			entry := model[len(model)-len(l.tail)+i]
			if !strings.HasPrefix(deny, entry.action+"/") || !strings.HasSuffix(deny, "+"+entry.pattern) {
				t.Fatalf("protected tail order: %q", deny)
			}
		}
		if model.count("deny", "/**/.env", "all") != 1 {
			t.Fatal("protected lookup deny missing")
		}
	}
}
