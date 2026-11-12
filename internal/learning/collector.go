// Package learning collects bounded, review-only permission-check candidates.
// A warn record is not evidence that an operation succeeded. This package does
// not run Syd, authorize, persist, or activate a profile.
package learning

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/network"
	"github.com/Gobd/syd-guard/internal/syd"
)

const (
	maxLine          = 64 << 10
	maxEntries       = 4096
	maxBytes         = 128 << 10
	maxExcludedRoots = 128
)

// Policy identifies runtime-only paths. Temporary and PolicyDirectory are
// required; ExcludedRoots must include all other control/state paths and any
// additional runtime baselines. These paths are excluded, not learned.
type Policy struct {
	Name            string
	PolicyDirectory string
	Temporary       string
	ExcludedRoots   []string
	// Set only when the actual Syd profile has log/rlimit_interval:0.
	RateLimitDisabled bool
}

type Counts struct {
	Lines       uint64 `json:"lines"`
	Rejected    uint64 `json:"rejected"`
	Dropped     uint64 `json:"dropped"`
	FileChecks  uint64 `json:"file_checks"`
	PublicDials uint64 `json:"public_dials"`
}

type ProfileCandidate struct {
	Profile    config.Profile `json:"profile"`
	Kind       string         `json:"kind"`
	Incomplete bool           `json:"incomplete"`
	Reasons    []string       `json:"reasons"`
	Counts     Counts         `json:"counts"`
}

type Collector struct {
	mu                          sync.Mutex
	policy                      Policy
	excluded                    []string
	files                       map[string]uint8
	dials                       map[network.Target]bool
	entries, bytes              int
	counts                      Counts
	reasons                     map[string]bool
	draining, drained, finished bool
}

// New requires trusted, absolute runtime paths. Root cannot be excluded or
// learned; excluding it would silently discard every event.
func New(p Policy) (*Collector, error) {
	if err := config.ProfileName(p.Name); err != nil {
		return nil, err
	}
	if len(p.ExcludedRoots) > maxExcludedRoots {
		return nil, errors.New("too many excluded roots")
	}
	roots := append([]string{"/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/dev", "/proc", "/sys", p.Temporary, p.PolicyDirectory}, p.ExcludedRoots...)
	for i, root := range roots {
		if !safePath(root) {
			return nil, fmt.Errorf("invalid excluded root")
		}
		roots[i] = filepath.Clean(root)
		// Check both spelling and resolved form for symlinked runtime roots.
		if resolved, err := resolvePath(root); err == nil && resolved != root {
			roots = append(roots, resolved)
		} else if err != nil {
			return nil, fmt.Errorf("cannot resolve excluded root: %w", err)
		}
	}
	c := &Collector{policy: p, excluded: roots, files: map[string]uint8{}, dials: map[network.Target]bool{}, reasons: map[string]bool{}}
	if !p.RateLimitDisabled {
		c.reasons["rate-limit-not-disabled"] = true
	}
	return c, nil
}

func safePath(path string) bool {
	return utf8.ValidString(path) && filepath.IsAbs(path) && path != "/" && filepath.Clean(path) == path && len(path) <= 4096 && !strings.ContainsAny(path, "*?[]{}\\$;!") && strings.IndexFunc(path, unicode.IsControl) < 0
}

// resolvePath resolves all existing ancestors even when the final component was
// removed by a rename/delete; errors other than nonexistence are not ignored.
func resolvePath(path string) (string, error) {
	current := path
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return resolved, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		// A dangling symlink is not a missing literal path. Its target cannot
		// be safely checked by walking only its lexical parent.
		if info, statErr := os.Lstat(current); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
			return "", err
		} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return "", statErr
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", err
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}

func within(path, root string) bool {
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

func (c *Collector) excludedPath(path, resolved string) (bool, error) {
	if syd.ProtectedPath(path, "write", c.policy.PolicyDirectory) || syd.ProtectedPath(resolved, "write", c.policy.PolicyDirectory) {
		return true, nil
	}
	for _, root := range c.excluded {
		current, err := resolvePath(root)
		if err != nil || !safePath(current) {
			return false, errors.New("excluded root resolution failed")
		}
		for _, spelling := range []string{root, current} {
			if within(path, spelling) || within(resolved, spelling) || within(spelling, path) || within(spelling, resolved) {
				return true, nil
			}
		}
	}
	return false, nil
}

// Drain consumes the dedicated trusted SYD_LOG_FD stream until EOF. Oversized
// lines and capacity overflow are dropped while the pipe continues to drain.
// It must be run concurrently with the workload, exactly once.
func (c *Collector) Drain(r io.Reader) error {
	c.mu.Lock()
	if c.draining || c.drained {
		c.mu.Unlock()
		return errors.New("drain already started")
	}
	c.draining = true
	c.mu.Unlock()
	reader := bufio.NewReaderSize(r, 32<<10)
	line := make([]byte, 0, maxLine)
	oversized := false
	var readErr error
	for {
		part, err := reader.ReadSlice('\n')
		if !oversized && len(line)+len(part) <= maxLine {
			line = append(line, part...)
		} else {
			oversized = true
			line = line[:0]
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if len(part) > 0 || len(line) > 0 || oversized {
			c.mu.Lock()
			c.counts.Lines++
			if oversized {
				c.counts.Dropped++
				c.reasons["line-too-long"] = true
			} else {
				c.consume(line)
			}
			c.mu.Unlock()
			line = line[:0]
			oversized = false
		}
		if err != nil {
			if err != io.EOF {
				readErr = err
			}
			break
		}
	}
	c.mu.Lock()
	c.draining = false
	c.drained = true
	if readErr != nil {
		c.reasons["log-read-error"] = true
	}
	c.mu.Unlock()
	return readErr
}

// decodeObject rejects duplicate keys at every level and excessive nesting,
// avoiding ambiguous trusted-field interpretations without retaining raw data.
func decodeObject(line []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(line) {
		return nil, errors.New("invalid utf8")
	}
	d := json.NewDecoder(strings.NewReader(string(line)))
	if err := checkValue(d, 0); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(line, &obj); err != nil || obj == nil {
		return nil, errors.New("invalid object")
	}
	return obj, nil
}

func checkValue(d *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("too deep")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return err
			}
			s, ok := k.(string)
			key := strings.ToLower(s)
			if !ok || seen[key] {
				return errors.New("duplicate key")
			}
			seen[key] = true
			if err := checkValue(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := checkValue(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("bad delimiter")
	}
	_, err = d.Token()
	return err
}
func (c *Collector) reject(reason string) { c.counts.Rejected++; c.reasons[reason] = true }

// jsonString rejects null, which encoding/json otherwise accepts for strings.
func jsonString(raw json.RawMessage) (string, bool) {
	var value string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	return value, true
}

func (c *Collector) consume(line []byte) {
	obj, err := decodeObject(line)
	if err != nil {
		c.reject("malformed-log")
		return
	}
	// Reserved fields must use their exact spelling, even when an unrelated
	// field has a case variant. Unknown fields are never copied to output.
	for key := range obj {
		lower := strings.ToLower(key)
		switch lower {
		case "ctx", "act", "version", "path", "cap":
			if key != lower {
				c.reject("malformed-log")
				return
			}
		}
	}
	ctx, ok := jsonString(obj["ctx"])
	if !ok || ctx != "access" {
		c.reject("unsupported-record")
		return
	}
	act, ok := jsonString(obj["act"])
	if !ok {
		c.reject("malformed-access")
		return
	}
	switch act {
	case "warn", "allow", "deny":
	default:
		c.reject("unsupported-record")
		return
	}
	if v, ok := obj["version"]; ok {
		var n int
		if json.Unmarshal(v, &n) != nil || n != 1 {
			c.reject("unsupported-log-version")
			return
		}
	}
	var caps []json.RawMessage
	if _, ok := jsonString(obj["cap"]); ok {
		caps = []json.RawMessage{obj["cap"]}
	} else if len(obj["cap"]) == 0 || obj["cap"][0] != '[' || json.Unmarshal(obj["cap"], &caps) != nil || len(caps) == 0 || len(caps) > 32 {
		c.reject("invalid-capabilities")
		return
	}
	capStrings := make([]string, 0, len(caps))
	for _, raw := range caps {
		cap, ok := jsonString(raw)
		if !ok || cap == "" {
			c.reject("invalid-capabilities")
			return
		}
		capStrings = append(capStrings, cap)
	}
	// Only explicit access/allow and access/deny records with typed caps and
	// an optional string path are ignored. Network caps are not file groups.
	if act != "warn" {
		if raw, present := obj["path"]; present {
			if path, ok := jsonString(raw); !ok || path == "" {
				c.reject("invalid-path")
			}
		}
		return
	}
	path, ok := jsonString(obj["path"])
	if !ok || !safePath(path) {
		c.reject("invalid-path")
		return
	}
	var bits uint8
	for _, cap := range capStrings {
		switch cap {
		case "read", "stat", "readdir", "chdir", "readlink":
			bits |= 1
		case "write", "create", "truncate", "chmod", "chattr", "mkdir", "symlink":
			bits |= 2
		case "delete", "rmdir", "rename":
			bits |= 4
		default:
			c.reject("unsupported-capability")
			return
		}
	}
	resolved, err := resolvePath(path)
	if err != nil || !safePath(resolved) {
		c.reject("path-resolution-failed")
		return
	}
	excluded, err := c.excludedPath(path, resolved)
	if err != nil {
		c.reject("path-resolution-failed")
		return
	}
	if excluded {
		return
	}
	c.counts.FileChecks++
	old := c.files[path]
	add := bits &^ old
	for _, bit := range []uint8{1, 2, 4} {
		if add&bit == 0 {
			continue
		}
		cost := len(path) + 16
		if c.entries >= maxEntries || c.bytes+cost > maxBytes {
			c.counts.Dropped++
			c.reasons["candidate-limit"] = true
			continue
		}
		c.files[path] |= bit
		c.entries++
		c.bytes += cost
	}
}

// OnPublicDial is only for the trusted gateway after a successful vetted public
// TCP dial and its session-closed check, before copying application data. It is
// not a DNS, failed-dial, payload, or application-success callback.
func (c *Collector) OnPublicDial(host string, port uint16, transport string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.finished {
		c.reasons["late-public-dial"] = true
		return errors.New("collector already finished")
	}
	target, err := network.Canonical(host, port)
	if err != nil || transport != "tcp" {
		c.counts.Rejected++
		c.reasons["invalid-public-dial"] = true
		return errors.New("invalid public dial")
	}
	if network.ReservedServiceHost(target.Host) {
		return nil
	}
	c.counts.PublicDials++
	if c.dials[target] {
		return nil
	}
	cost := len(target.Host) + 16
	if c.entries >= maxEntries || c.bytes+cost > maxBytes {
		c.counts.Dropped++
		c.reasons["candidate-limit"] = true
		return errors.New("candidate limit reached")
	}
	c.dials[target] = true
	c.entries++
	c.bytes += cost
	return nil
}

// Outcome is supplied by the trusted launcher after waiting for the workload.
// Errors and signals are used only as flags and are never serialized.
type Outcome struct {
	ExitCode      int
	Err           error
	Signal        os.Signal
	Cancelled     bool
	ScannerError  error
	DeliveryError error
}

// FinishOutcome reports all known launcher and delivery failures. It does not
// wait for Drain or dial callbacks; the caller must quiesce both first.
func (c *Collector) FinishOutcome(outcome Outcome) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.finished = true
	if outcome.ExitCode != 0 || outcome.Err != nil || outcome.Signal != nil || outcome.Cancelled {
		c.reasons["abnormal-exit"] = true
	}
	if outcome.ScannerError != nil {
		c.reasons["scanner-error"] = true
	}
	if outcome.DeliveryError != nil {
		c.reasons["delivery-error"] = true
	}
}

// Finish cannot describe Run's (nonzero, nil) outcome and always records that
// the full workload outcome is unknown. Prefer FinishOutcome or Stream.Finish.
func (c *Collector) Finish(exitErr error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.finished = true
	c.reasons["workload-outcome-unknown"] = true
	if exitErr != nil {
		c.reasons["abnormal-exit"] = true
	}
}

// Snapshot returns a detached, deterministically sorted candidate. Pending
// drain/exit and known loss make it incomplete; no activation API is provided.
func (c *Collector) Snapshot() ProfileCandidate {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := config.Profile{Version: 1, Name: c.policy.Name, Files: []config.FileRule{}, Network: []config.NetworkRule{}}
	paths := make([]string, 0, len(c.files))
	for path := range c.files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		var access []string
		for _, g := range []struct {
			bit  uint8
			name string
		}{{1, "read"}, {2, "write"}, {4, "delete"}} {
			if c.files[path]&g.bit != 0 {
				access = append(access, g.name)
			}
		}
		p.Files = append(p.Files, config.FileRule{Path: path, Access: access})
	}
	for target := range c.dials {
		p.Network = append(p.Network, config.NetworkRule{Host: target.Host, Port: target.Port, Transport: target.Transport})
	}
	sort.Slice(p.Network, func(i, j int) bool {
		if p.Network[i].Host == p.Network[j].Host {
			return p.Network[i].Port < p.Network[j].Port
		}
		return p.Network[i].Host < p.Network[j].Host
	})
	reasons := make([]string, 0, len(c.reasons)+2)
	for reason := range c.reasons {
		reasons = append(reasons, reason)
	}
	if !c.drained {
		reasons = append(reasons, "log-not-drained")
	}
	if !c.finished {
		reasons = append(reasons, "workload-not-finished")
	}
	sort.Strings(reasons)
	return ProfileCandidate{Profile: p, Kind: "permission-check-candidate", Incomplete: len(reasons) > 0, Reasons: reasons, Counts: c.counts}
}
