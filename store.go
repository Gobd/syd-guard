package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultRulesName = ".sydguard.json" // <project>/.sydguard.json
	rulesDirName     = ".sydguard"      // <project>/.sydguard/<name>.json via --rules NAME
)

// rulesFileFor resolves --rules: "" = default file, NAME = .sydguard/NAME.json,
// anything with a slash or .json suffix = a path (relative to cwd).
func rulesFileFor(project, cwd, spec string) (string, error) {
	switch {
	case spec == "":
		return filepath.Join(project, defaultRulesName), nil
	case !strings.ContainsRune(spec, '/') && !strings.HasSuffix(spec, ".json"):
		if strings.HasPrefix(spec, ".") || safeText(spec) != nil {
			return "", fmt.Errorf("bad rules name %q", spec)
		}
		return filepath.Join(project, rulesDirName, spec+".json"), nil
	}
	p := expandHome(spec)
	if !filepath.IsAbs(p) {
		p = filepath.Join(cwd, p)
	}
	p = filepath.Clean(p)
	return p, safePath(p)
}

func hashOf(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

// readRulesFile reads a rules file defensively: regular file, owned by us,
// one hard link (a second link could let the sandbox edit it), <1 MiB.
// A missing file is an empty, trusted rule set.
func readRulesFile(path string) (Rules, []byte, error) {
	if err := safePath(path); err != nil {
		return Rules{}, nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return Rules{}, nil, nil
	} else if err != nil {
		return Rules{}, nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return Rules{}, nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.Mode().IsRegular():
		return Rules{}, nil, fmt.Errorf("%s is not a regular file", path)
	case ok && int(st.Uid) != os.Getuid():
		return Rules{}, nil, fmt.Errorf("%s is not owned by you", path)
	case ok && st.Nlink != 1:
		return Rules{}, nil, fmt.Errorf("%s has %d hard links; remove the extra links", path, st.Nlink)
	}
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return Rules{}, nil, err
	}
	var r Rules
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return Rules{}, data, fmt.Errorf("%s: %w", path, err)
	}
	return r, data, nil
}

func writeRulesFile(path string, r Rules) ([]byte, error) {
	if err := safePath(path); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	data, _ := json.MarshalIndent(r, "", "  ")
	data = append(data, '\n')
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return nil, err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	return data, os.Rename(tmp, path) // new inode: old hard links can't follow
}

// Trust: the hash of the last content sydguard wrote or you accepted, per file.
// The sandbox can't write rules files by path, and any change made another way
// (hard link, editor, git pull, cloned repo) is ignored until trusted again.
func trustPath(file string) string {
	sum := sha256.Sum256([]byte(file))
	return filepath.Join(configDir(), "trusted", hex.EncodeToString(sum[:12]))
}

func trust(file string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(trustPath(file)), 0o700); err != nil {
		return err
	}
	return os.WriteFile(trustPath(file), []byte(file+"\n"+hashOf(data)+"\n"), 0o600)
}

func trusted(file string, data []byte) bool {
	if data == nil {
		return true
	}
	b, err := os.ReadFile(trustPath(file))
	return err == nil && strings.HasSuffix(strings.TrimSpace(string(b)), hashOf(data))
}

func knownRulesFiles() []string {
	files, _ := filepath.Glob(filepath.Join(configDir(), "trusted", "*"))
	var out []string
	for _, f := range files {
		if b, err := os.ReadFile(f); err == nil {
			if p, _, ok := strings.Cut(string(b), "\n"); ok && safePath(p) == nil {
				out = append(out, p)
			}
		}
	}
	return out
}

// ruleStore caches trusted rules in memory so the proxy and live updates never
// act on untrusted bytes. All writes go through it.
type ruleStore struct {
	mu    sync.Mutex
	files map[string]*ruleFile
}

type ruleFile struct {
	Path     string `json:"path"`
	Rules    Rules  `json:"rules"`             // last trusted content
	Pending  string `json:"pending,omitempty"` // untrusted content on disk, if any
	Error    string `json:"error,omitempty"`
	checked  time.Time
	modTime  time.Time
	size     int64
	loadedOK bool
}

func newRuleStore() *ruleStore { return &ruleStore{files: map[string]*ruleFile{}} }

// get returns the trusted rules for path, re-checking the disk at most every 500ms.
func (s *ruleStore) get(path string) Rules {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refreshLocked(path).Rules.clone()
}

func (s *ruleStore) view(path string) ruleFile {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := *s.refreshLocked(path)
	f.Rules = f.Rules.clone()
	return f
}

func (s *ruleStore) refreshLocked(path string) *ruleFile {
	f, ok := s.files[path]
	if !ok {
		f = &ruleFile{Path: path}
		s.files[path] = f
	}
	if time.Since(f.checked) < 500*time.Millisecond {
		return f
	}
	f.checked = time.Now()
	if fi, err := os.Lstat(path); err == nil && f.loadedOK && fi.ModTime().Equal(f.modTime) && fi.Size() == f.size {
		return f
	} else if err == nil {
		f.modTime, f.size = fi.ModTime(), fi.Size()
	}
	r, data, err := readRulesFile(path)
	f.Error, f.Pending = "", ""
	switch {
	case err != nil:
		f.Error = err.Error() // keep the last trusted rules
	case trusted(path, data):
		f.Rules, f.loadedOK = r, true
	default:
		f.Pending = string(data) // changed outside sydguard: keep last trusted rules
		if !f.loadedOK {
			f.Rules = Rules{}
		}
	}
	return f
}

// edit applies fn to the trusted rules and saves them (fails if the file on
// disk has untrusted changes, so nothing is silently overwritten).
func (s *ruleStore) edit(path string, fn func(*Rules) error) (before, after Rules, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.refreshLocked(path)
	if f.Pending != "" {
		return before, after, fmt.Errorf("%s changed outside sydguard; trust or revert it first", path)
	}
	if f.Error != "" {
		return before, after, errors.New(f.Error)
	}
	before = f.Rules.clone()
	next := f.Rules.clone()
	if err := fn(&next); err != nil {
		return before, after, err
	}
	data, err := writeRulesFile(path, next)
	if err != nil {
		return before, after, err
	}
	if err := trust(path, data); err != nil {
		return before, after, err
	}
	f.Rules, f.loadedOK, f.checked = next, true, time.Time{}
	return before, next.clone(), nil
}

// trustCurrent accepts whatever is on disk now.
func (s *ruleStore) trustCurrent(path string) (before, after Rules, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.refreshLocked(path)
	before = f.Rules.clone()
	r, data, err := readRulesFile(path)
	if err != nil {
		return before, before, err
	}
	if err := trust(path, data); err != nil {
		return before, before, err
	}
	f.Rules, f.Pending, f.loadedOK, f.checked = r, "", true, time.Time{}
	return before, r.clone(), nil
}

// replace overwrites a file with the given rules (used to mirror global rules).
func (s *ruleStore) replace(path string, r Rules) (before, after Rules, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.refreshLocked(path)
	before = f.Rules.clone()
	data, err := writeRulesFile(path, r)
	if err != nil {
		return before, before, err
	}
	if err := trust(path, data); err != nil {
		return before, before, err
	}
	f.Rules, f.Pending, f.Error, f.loadedOK, f.checked = r.clone(), "", "", true, time.Time{}
	return before, r.clone(), nil
}

func addRule(kind, pattern string) func(*Rules) error {
	return func(r *Rules) error {
		l := r.list(kind)
		if l == nil {
			return fmt.Errorf("unknown kind %q", kind)
		}
		for _, p := range *l {
			if p == pattern {
				return nil
			}
		}
		*l = append(*l, pattern)
		return nil
	}
}

func removeRule(kind, pattern string) func(*Rules) error {
	return func(r *Rules) error {
		l := r.list(kind)
		if l == nil {
			return fmt.Errorf("unknown kind %q", kind)
		}
		for i, p := range *l {
			if p == pattern {
				*l = append((*l)[:i], (*l)[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("rule not found")
	}
}

// diffCommands returns the Syd commands that turn rule set a into b.
func diffCommands(a, b Rules) []string {
	var out []string
	for _, k := range []string{"read", "write", "connect"} {
		old, cur := map[string]bool{}, map[string]bool{}
		for _, p := range *a.list(k) {
			old[p] = true
		}
		for _, p := range *b.list(k) {
			cur[p] = true
		}
		for _, p := range *a.list(k) {
			if !cur[p] {
				if n, err := normalize(k, p); err == nil {
					out = append(out, sydCommands(k, n, "-")...)
				}
			}
		}
		for _, p := range *b.list(k) {
			if !old[p] {
				if n, err := normalize(k, p); err == nil {
					out = append(out, sydCommands(k, n, "+")...)
				}
			}
		}
	}
	return out
}
