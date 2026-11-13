package syd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unicode/utf8"

	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/managedlaunch"
)

// Live banks are a source-only protocol, not an IPC transport or launch mode.
// The caller must authenticate the pinned engine bytes and exclusive writer,
// preauthorize sufficient startup Landlock and mount ceilings, and fail-stop the
// entire session after a rejected, incomplete, or uncertain update. Neither the
// compiler nor a version string proves any of those runtime requirements.
const liveBankEngineSHA256 = "523122c5dcc5f3b65b68b58fd642086d80aaa76c5c2e9825efc47b1750c69d01"
const liveBankMaxRules = 128
const liveBankMaxBytes = 256 * 1024

// FixedReleaseFD is the only release descriptor consumed by the fixed gate.
const FixedReleaseFD = 3

// BankBinding identifies an externally authenticated session and project. IDs
// are opaque 256-bit lowercase hex; Generation must never be reused in a session.
type BankBinding struct {
	Session, Project, Profile string
	Generation                uint64
}

// BankReceipt binds a completed revision to its session and monotonically
// increasing update sequence. It is not evidence of authenticated IPC delivery.
type BankReceipt struct {
	Binding  BankBinding
	Sequence uint64
	Revision string
}

// BankBatch owns the exact bytes to submit as one ordered load. The caller must
// not execute a prefix as if it were a successful update.
type BankBatch struct {
	Receipt BankReceipt
	data    []byte
}

func (b BankBatch) Bytes() []byte { return append([]byte(nil), b.data...) }

// BankLedger serializes one session's compiler state. Do not copy after use.
type BankLedger struct {
	mu                 sync.Mutex
	binding            BankBinding
	workdir, temporary string
	protected          []string
	base, tail         []string
	startupACL         []string
	startupFingerprint string
	inventories        [2][]string
	active             int // -1 means restrictive default
	receipt            BankReceipt
	pending            *bankPending
	stopped            bool
}

type bankPending struct {
	batch     BankBatch
	bank      int
	inventory []string
}

func bankLinesValid(lines []string) bool {
	for _, line := range lines {
		// Syd's configuration reader and field parser impose a 4096-byte limit.
		if !utf8.ValidString(line) || len(line) >= 4096 {
			return false
		}
	}
	return true
}

func bankHexID(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

// NewBankLedger returns a startup profile and an initially restrictive ledger.
// EngineDigest is an identity assertion from the trusted caller, not validation
// of an executable or installation. Stock 3.59 must never use this protocol.
func NewBankLedger(binding BankBinding, engineDigest, workdir, temporary, socket string, protected []string, requirePIE bool) (*BankLedger, string, error) {
	if !bankHexID(binding.Session) || !bankHexID(binding.Project) || config.ProfileName(binding.Profile) != nil || binding.Generation == 0 || engineDigest != liveBankEngineSHA256 {
		return nil, "", fmt.Errorf("invalid bank binding or engine safety identity")
	}
	if len(protected) > 64 || len(socket) >= 108 || !utf8.ValidString(socket) || literalPath(socket) != nil || filepath.Clean(socket) != socket {
		return nil, "", fmt.Errorf("invalid bank startup inputs")
	}
	workdir, err := canonicalDirectory(workdir)
	if err != nil {
		return nil, "", err
	}
	temporary, err = canonicalDirectory(temporary)
	if err != nil {
		return nil, "", err
	}
	resolvedSocket, err := config.RevalidateResolvedFilePath(socket)
	if err != nil || resolvedSocket != socket || pathOverlaps(socket, workdir) || pathOverlaps(socket, temporary) {
		return nil, "", fmt.Errorf("IPC socket must be canonical and outside project and scratch")
	}
	// Path denies supplement, but do not replace, authenticated socket isolation.
	protected = append(append([]string(nil), protected...), socket)
	for _, p := range protected {
		if len(p) > 4096 {
			return nil, "", fmt.Errorf("protected path too long")
		}
	}
	profile, err := StrictProfile(workdir, temporary, protected, config.ResolvedProfile{})
	if err != nil {
		return nil, "", err
	}
	tail, err := ProtectedRules(workdir, protected)
	if err != nil {
		return nil, "", err
	}
	if !strings.HasSuffix(profile, tail) {
		return nil, "", fmt.Errorf("invalid baseline tail")
	}
	base := strings.Split(strings.TrimSuffix(strings.TrimSuffix(profile, tail), "\n"), "\n")
	// These categories default off and cannot be enabled after launch. Enable
	// them before cloning so protected chdir/readlink denies are enforced.
	startup := profile + "sandbox/chdir:on\nsandbox/readlink:on\n"
	if requirePIE {
		startup += "trace/allow_unsafe_exec_nopie:0\n"
	}
	startup += "domain+@sgbankA:@default\ndomain+@sgbankB:@default\nipc:" + socket + "\nlock:ipc\n"
	if len(startup) > liveBankMaxBytes || !bankLinesValid(strings.Split(startup, "\n")) {
		return nil, "", fmt.Errorf("startup profile exceeds limit")
	}
	l := &BankLedger{binding: binding, workdir: workdir, temporary: temporary, protected: append([]string(nil), protected...), base: base, tail: strings.Split(strings.TrimSuffix(tail, "\n"), "\n"), active: -1}
	l.receipt = BankReceipt{Binding: binding}
	return l, startup, nil
}

// RootWriterStartup is fixed internal startup authority, not saved profile data.
// Its gate inode must be independently verified against the ROOT-held FD.
type RootWriterStartup struct {
	GatePath         string
	GateDev, GateIno uint64
	UID, GID         uint32
	ReleaseFD        int
	WholeProjectRWD  bool
	RequirePIE       bool
}

// NewRootWriterBankLedger compiles only the reviewed fixed ROOT-writer mode.
// The digest remains an assertion: callers must independently hash the held FD.
func NewRootWriterBankLedger(binding BankBinding, engineDigest, workdir, temporary, socket string, protected []string, spec RootWriterStartup) (*BankLedger, string, error) {
	if spec.UID == 0 || spec.GID == 0 || spec.GateDev == 0 || spec.GateIno == 0 || spec.ReleaseFD != FixedReleaseFD || !spec.WholeProjectRWD || literalPath(spec.GatePath) != nil || filepath.Clean(spec.GatePath) != spec.GatePath {
		return nil, "", fmt.Errorf("invalid root writer startup authority")
	}
	gate, err := config.RevalidateResolvedFilePath(spec.GatePath)
	if err != nil || gate != spec.GatePath || pathOverlaps(gate, workdir) || pathOverlaps(gate, temporary) {
		return nil, "", fmt.Errorf("invalid fixed gate path")
	}
	info, err := os.Lstat(gate)
	if err != nil || !info.Mode().IsRegular() {
		return nil, "", fmt.Errorf("invalid fixed gate file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Dev) != spec.GateDev || uint64(stat.Ino) != spec.GateIno {
		return nil, "", fmt.Errorf("fixed gate identity changed")
	}
	for _, p := range protected {
		if pathOverlaps(gate, p) {
			return nil, "", fmt.Errorf("gate overlaps protected authority")
		}
	}
	ledger, startup, err := NewBankLedger(binding, engineDigest, workdir, temporary, socket, protected, spec.RequirePIE)
	if err != nil {
		return nil, "", err
	}
	if pathOverlaps(gate, ledger.workdir) || pathOverlaps(gate, ledger.temporary) {
		return nil, "", fmt.Errorf("gate overlaps canonical project or scratch")
	}
	gateACL := []string{"allow/read,stat,exec+" + gate, "allow/lock/read,exec+" + gate, "allow/lock/read,readdir,write,create,delete,rename,truncate,mkdir,rmdir,symlink+" + ledger.workdir}
	ledger.startupACL = append([]string(nil), gateACL...)
	ledger.base = append(ledger.base, gateACL...)
	tail := strings.Join(ledger.tail, "\n") + "\n"
	if !strings.Contains(startup, tail) {
		return nil, "", fmt.Errorf("invalid root writer baseline")
	}
	startup = strings.Replace(startup, tail, strings.Join(gateACL, "\n")+"\n"+tail, 1)
	marker := "domain+@sgbankA:@default\n"
	settings := fmt.Sprintf("ipc/uid:0\nipc/gid:0\npassfd^\npassfd+stdio,%d\n", spec.ReleaseFD)
	if !strings.Contains(startup, marker) {
		return nil, "", fmt.Errorf("invalid root writer startup")
	}
	startup = strings.Replace(startup, marker, settings+marker, 1)
	if len(startup) > liveBankMaxBytes || !bankLinesValid(strings.Split(startup, "\n")) {
		return nil, "", fmt.Errorf("root writer startup exceeds limit")
	}
	material, err := json.Marshal(struct {
		Binding                    BankBinding
		EngineDigest               string
		WriterUID, WriterGID       uint32
		Workdir, Temporary, Socket string
		Protected                  []string
		Spec                       RootWriterStartup
	}{binding, engineDigest, 0, 0, ledger.workdir, ledger.temporary, socket, append([]string(nil), protected...), spec})
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(material)
	ledger.startupFingerprint = hex.EncodeToString(sum[:])
	return ledger, startup, nil
}

// StartupFingerprint is a local immutable-spec identifier, not IPC proof.
func (l *BankLedger) StartupFingerprint() string { return l.startupFingerprint }

// Prepare parses the exact submitted intent bytes and verifies the preceding
// receipt. It makes no runtime changes and allows only one outstanding batch.
// The caller must not mutate intent concurrently with this call.
func (l *BankLedger) Prepare(expected BankReceipt, intent []byte) (BankBatch, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stopped || l.pending != nil || expected != l.receipt || l.receipt.Sequence == ^uint64(0) {
		return BankBatch{}, fmt.Errorf("stopped, busy, or stale bank ledger")
	}
	if len(intent) > liveBankMaxBytes {
		return BankBatch{}, fmt.Errorf("intent too large")
	}
	snapshot, err := config.ParseManagedProfileSnapshot(l.binding.Profile, intent)
	if err != nil {
		return BankBatch{}, err
	}
	p := snapshot.Profile()
	if len(p.Files) > liveBankMaxRules {
		return BankBatch{}, fmt.Errorf("too many file rules")
	}
	if _, err = managedlaunch.ValidateIntent(p); err != nil {
		return BankBatch{}, err
	}
	resolved, err := config.ResolveProfile(snapshot, l.workdir, "", []string{l.workdir}, l.protected)
	if err != nil {
		return BankBatch{}, err
	}
	compiled, err := StrictProfile(l.workdir, l.temporary, l.protected, resolved)
	if err != nil {
		return BankBatch{}, err
	}
	basePrefix := strings.Join(l.base, "\n") + "\n"
	if len(l.startupACL) != 0 {
		plain := strings.Join(l.base[:len(l.base)-len(l.startupACL)], "\n") + "\n"
		if !strings.HasPrefix(compiled, plain) {
			return BankBatch{}, fmt.Errorf("baseline changed")
		}
		compiled = plain + strings.Join(l.startupACL, "\n") + "\n" + strings.TrimPrefix(compiled, plain)
	}
	tail := strings.Join(l.tail, "\n") + "\n"
	if !strings.HasPrefix(compiled, basePrefix) || !strings.HasSuffix(compiled, tail) {
		return BankBatch{}, fmt.Errorf("baseline changed")
	}
	middle := strings.TrimSuffix(strings.TrimPrefix(compiled, basePrefix), tail)
	var inventory []string
	for _, line := range strings.Split(strings.TrimSuffix(middle, "\n"), "\n") {
		if line != "" && !strings.HasPrefix(line, "allow/lock/") {
			inventory = append(inventory, line)
		}
	}
	if len(inventory) > 2048 {
		return BankBatch{}, fmt.Errorf("expanded inventory exceeds limit")
	}
	bank := 0
	if l.active == 0 {
		bank = 1
	}
	name := []string{"sgbankA", "sgbankB"}[bank]
	lines := []string{"cmd/move!default"}
	// Remove all known previous dynamic grants, plus baseline allows sharing a
	// pattern with one of those grants; restore those baseline entries exactly.
	patterns := map[string]bool{}
	for _, line := range l.inventories[bank] {
		if i := strings.IndexByte(line, '+'); i >= 0 {
			patterns[line[i+1:]] = true
		}
	}
	var restore []string
	for _, line := range l.base {
		i := strings.IndexByte(line, '+')
		if i >= 0 && strings.HasPrefix(line, "allow/") && !strings.HasPrefix(line, "allow/lock/") && patterns[line[i+1:]] {
			restore = append(restore, line)
		}
	}
	remove := append(append(append([]string(nil), l.inventories[bank]...), restore...), l.tail...)
	for _, line := range remove {
		i := strings.IndexByte(line, '+')
		if i < 0 {
			return BankBatch{}, fmt.Errorf("invalid owned ACL inventory")
		}
		lines = append(lines, "@"+name+"/"+line[:i]+"^"+line[i+1:])
	}
	for _, line := range append(append(restore, inventory...), l.tail...) {
		lines = append(lines, "@"+name+"/"+line)
	}
	lines = append(lines, "cmd/move!"+name)
	data := []byte(strings.Join(lines, "\n") + "\n")
	if len(data) > liveBankMaxBytes || !bankLinesValid(lines) {
		return BankBatch{}, fmt.Errorf("batch exceeds limit")
	}
	receipt := BankReceipt{Binding: l.binding, Sequence: l.receipt.Sequence + 1, Revision: snapshot.Revision()}
	batch := BankBatch{Receipt: receipt, data: data}
	l.pending = &bankPending{batch: batch, bank: bank, inventory: inventory}
	return BankBatch{Receipt: receipt, data: append([]byte(nil), data...)}, nil
}

// Finish accepts only an independently authenticated ACK for this exact batch.
// Any failure or lost ACK irrevocably quarantines both banks and the session.
func (l *BankLedger) Finish(receipt BankReceipt, acknowledged bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stopped || l.pending == nil || l.pending.batch.Receipt != receipt {
		l.pending = nil
		l.stopped = true
		return fmt.Errorf("stale or unknown bank receipt: fail-stop required")
	}
	if !acknowledged {
		l.pending = nil
		l.stopped = true
		return fmt.Errorf("uncertain or failed bank update: fail-stop required")
	}
	l.active = l.pending.bank
	l.inventories[l.active] = l.pending.inventory
	l.receipt = receipt
	l.pending = nil
	return nil
}

// Stop permanently quarantines the ledger, including failures before Prepare.
func (l *BankLedger) Stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pending = nil
	l.stopped = true
}

// InitialReceipt is the only accepted predecessor for the first update.
func (l *BankLedger) InitialReceipt() BankReceipt { return BankReceipt{Binding: l.binding} }
