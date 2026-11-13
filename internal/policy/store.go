package policy

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

	"github.com/Gobd/syd-guard/internal/system"
)

const (
	DefaultRulesName = ".sydguard.json" // <project>/.sydguard.json
	RulesDirName     = ".sydguard"      // <project>/.sydguard/<name>.json via --rules NAME
)

// RulesFileFor resolves --rules: "" = default file, NAME = .sydguard/NAME.json,
// anything with a slash or .json suffix = a path (relative to cwd).
func RulesFileFor(project, cwd, spec string) (string, error) {
	switch {
	case spec == "":
		return filepath.Join(project, DefaultRulesName), nil
	case !strings.ContainsRune(spec, '/') && !strings.HasSuffix(spec, ".json"):
		if strings.HasPrefix(spec, ".") || system.SafeText(spec) != nil {
			return "", fmt.Errorf("bad rules name %q", spec)
		}
		return filepath.Join(project, RulesDirName, spec+".json"), nil
	}
	p := system.ExpandHome(spec)
	if !filepath.IsAbs(p) {
		p = filepath.Join(cwd, p)
	}
	p = filepath.Clean(p)
	return p, system.SafePath(p)
}

// ReadRulesFile reads a rules file defensively: regular file, owned by us,
// one hard link (a second link could let the sandbox edit it), <1 MiB.
// A missing file is an empty, Trusted rule set.
func ReadRulesFile(path string) (Rules, []byte, error) {
	if err := system.SafePath(path); err != nil {
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
	if err := system.SafePath(path); err != nil {
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
// (hard link, editor, git pull, cloned repo) is Ignored until Trusted again.
func trustPath(file string) string {
	sum := sha256.Sum256([]byte(file))
	return filepath.Join(system.ConfigDir(), "Trusted", hex.EncodeToString(sum[:12]))
}

func Trust(file string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(trustPath(file)), 0o700); err != nil {
		return err
	}
	return os.WriteFile(trustPath(file), []byte(file+"\n"+system.HashBytes(data)+"\n"), 0o600)
}

func Trusted(file string, data []byte) bool {
	if data == nil {
		return true
	}
	b, err := os.ReadFile(trustPath(file))
	return err == nil && strings.HasSuffix(strings.TrimSpace(string(b)), system.HashBytes(data))
}

func KnownRulesFiles() []string {
	files, _ := filepath.Glob(filepath.Join(system.ConfigDir(), "Trusted", "*"))
	var out []string
	for _, f := range files {
		if b, err := os.ReadFile(f); err == nil {
			if p, _, ok := strings.Cut(string(b), "\n"); ok && system.SafePath(p) == nil {
				out = append(out, p)
			}
		}
	}
	return out
}

// Store caches Trusted rules in memory so the proxy and live updates never
// act on untrusted bytes. All writes go through it.
type Store struct {
	mu    sync.Mutex
	files map[string]*RuleFile
}

type RuleFile struct {
	Path     string `json:"path"`
	Rules    Rules  `json:"rules"`             // last Trusted content
	Pending  string `json:"pending,omitempty"` // untrusted content on disk, if any
	Error    string `json:"error,omitempty"`
	checked  time.Time
	modTime  time.Time
	size     int64
	loadedOK bool
}

func NewStore() *Store { return &Store{files: map[string]*RuleFile{}} }

// get returns the Trusted rules for path, re-checking the disk at most every 500ms.
func (s *Store) Get(path string) Rules {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refreshLocked(path).Rules.Clone()
}

func (s *Store) View(path string) RuleFile {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := *s.refreshLocked(path)
	f.Rules = f.Rules.Clone()
	return f
}

func (s *Store) refreshLocked(path string) *RuleFile {
	f, ok := s.files[path]
	if !ok {
		f = &RuleFile{Path: path}
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
	r, data, err := ReadRulesFile(path)
	f.Error, f.Pending = "", ""
	switch {
	case err != nil:
		f.Error = err.Error() // keep the last Trusted rules
	case Trusted(path, data):
		f.Rules, f.loadedOK = r, true
	default:
		f.Pending = string(data) // changed outside sydguard: keep last Trusted rules
		if !f.loadedOK {
			f.Rules = Rules{}
		}
	}
	return f
}

// edit applies fn to the Trusted rules and saves them (fails if the file on
// disk has untrusted changes, so nothing is silently overwritten).
func (s *Store) Edit(path string, fn func(*Rules) error) (before, after Rules, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.refreshLocked(path)
	if f.Pending != "" {
		return before, after, fmt.Errorf("%s changed outside sydguard; Trust or revert it first", path)
	}
	if f.Error != "" {
		return before, after, errors.New(f.Error)
	}
	before = f.Rules.Clone()
	next := f.Rules.Clone()
	if err := fn(&next); err != nil {
		return before, after, err
	}
	data, err := writeRulesFile(path, next)
	if err != nil {
		return before, after, err
	}
	if err := Trust(path, data); err != nil {
		return before, after, err
	}
	f.Rules, f.loadedOK, f.checked = next, true, time.Time{}
	return before, next.Clone(), nil
}

// trustCurrent accepts whatever is on disk now.
func (s *Store) TrustCurrent(path string) (before, after Rules, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.refreshLocked(path)
	before = f.Rules.Clone()
	r, data, err := ReadRulesFile(path)
	if err != nil {
		return before, before, err
	}
	if err := Trust(path, data); err != nil {
		return before, before, err
	}
	f.Rules, f.Pending, f.loadedOK, f.checked = r, "", true, time.Time{}
	return before, r.Clone(), nil
}

// replace overwrites a file with the given rules (used to mirror global rules).
func (s *Store) Replace(path string, r Rules) (before, after Rules, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.refreshLocked(path)
	before = f.Rules.Clone()
	data, err := writeRulesFile(path, r)
	if err != nil {
		return before, before, err
	}
	if err := Trust(path, data); err != nil {
		return before, before, err
	}
	f.Rules, f.Pending, f.Error, f.loadedOK, f.checked = r.Clone(), "", "", true, time.Time{}
	return before, r.Clone(), nil
}

func AddRule(kind, pattern string) func(*Rules) error {
	return func(r *Rules) error {
		l := r.List(kind)
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

func RemoveRule(kind, pattern string) func(*Rules) error {
	return func(r *Rules) error {
		l := r.List(kind)
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

// DiffCommands returns the Syd commands that turn rule set a into b.
func DiffCommands(a, b Rules) []string {
	var out []string
	for _, k := range []string{"read", "write", "connect"} {
		old, cur := map[string]bool{}, map[string]bool{}
		for _, p := range *a.List(k) {
			old[p] = true
		}
		for _, p := range *b.List(k) {
			cur[p] = true
		}
		for _, p := range *a.List(k) {
			if !cur[p] {
				if n, err := Normalize(k, p); err == nil {
					out = append(out, SydCommands(k, n, "-")...)
				}
			}
		}
		for _, p := range *b.List(k) {
			if !old[p] {
				if n, err := Normalize(k, p); err == nil {
					out = append(out, SydCommands(k, n, "+")...)
				}
			}
		}
	}
	return out
}

func CleanRules(r Rules) (Rules, error) {
	var out Rules
	for _, k := range Kinds {
		for _, p := range *r.List(k) {
			n, err := Normalize(k, p)
			if err != nil {
				return out, err
			}
			*out.List(k) = append(*out.List(k), n)
		}
	}
	return out, nil
}

func ProjectOfRulesFile(file string) string {
	dir := filepath.Dir(file)
	if filepath.Base(dir) == RulesDirName {
		return filepath.Dir(dir)
	}
	if filepath.Base(file) == DefaultRulesName {
		return dir
	}
	return ""
}
