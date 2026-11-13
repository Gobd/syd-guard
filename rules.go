package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

// Rules is the whole user-facing policy language.
//
//	read/write: path globs. "*" = one path segment, "**" = anything,
//	            "/dir/**" (or Syd's "/dir/***") = dir and everything below.
//	hosts:      domain globs for the HTTP(S) proxy: "github.com", "*.github.com",
//	            optionally ":port". "*.x.com" does not match "x.com".
//	connect:    raw Syd network targets for tools that ignore the proxy, e.g.
//	            "140.82.112.3!22", "127.0.0.1!8080", "/run/user/1000/bus".
type Rules struct {
	Read    []string `json:"read,omitempty"`
	Write   []string `json:"write,omitempty"`
	Hosts   []string `json:"hosts,omitempty"`
	Connect []string `json:"connect,omitempty"`
	// Ignore: path or host globs that stay denied without asking again.
	Ignore []string `json:"ignore,omitempty"`
}

var kinds = []string{"read", "write", "hosts", "connect", "ignore"}

func (r *Rules) list(kind string) *[]string {
	switch kind {
	case "read":
		return &r.Read
	case "write":
		return &r.Write
	case "hosts":
		return &r.Hosts
	case "connect":
		return &r.Connect
	case "ignore":
		return &r.Ignore
	}
	return nil
}

func home() string { h, _ := os.UserHomeDir(); return h }

func configDir() string { return filepath.Join(home(), ".config", "sydguard") }
func stateDir() string  { return filepath.Join(home(), ".local", "state", "sydguard") }

const projectFile = ".sydguard.json"

// profilePath returns where rules live: <project>/.sydguard.json (committable;
// the sandbox can never write it), or the global file for project "".
func profilePath(project string) string {
	if project == "" {
		return filepath.Join(configDir(), "global.json")
	}
	return filepath.Join(project, projectFile)
}

func loadRulesBytes(project string) (Rules, []byte, error) {
	var r Rules
	data, err := os.ReadFile(profilePath(project))
	if errors.Is(err, os.ErrNotExist) {
		return Rules{}, nil, nil
	} else if err != nil {
		return Rules{}, nil, err
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return Rules{}, data, fmt.Errorf("%s: %w", profilePath(project), err)
	}
	return r, data, nil
}

func loadRules(project string) (Rules, error) {
	r, _, err := loadRulesBytes(project)
	return r, err
}

func saveRules(project string, r Rules) error {
	p := profilePath(project)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(r, "", "  ")
	data = append(data, '\n')
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	if project != "" {
		return trust(project, data)
	}
	return nil
}

// Trust: the hash of the last project file sydguard wrote or the user accepted.
// A file changed elsewhere (editor, git pull, cloned repo) must be re-trusted.
func trustPath(project string) string {
	sum := sha256.Sum256([]byte(project))
	return filepath.Join(configDir(), "trusted", hex.EncodeToString(sum[:12]))
}

func hashOf(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func trust(project string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(trustPath(project)), 0o700); err != nil {
		return err
	}
	return os.WriteFile(trustPath(project), []byte(project+"\n"+hashOf(data)+"\n"), 0o600)
}

func trusted(project string, data []byte) bool {
	if data == nil {
		return true // no file yet
	}
	b, err := os.ReadFile(trustPath(project))
	return err == nil && strings.HasSuffix(strings.TrimSpace(string(b)), hashOf(data))
}

// knownProjects lists every project sydguard has trusted, for the UI.
func knownProjects() []string {
	files, _ := filepath.Glob(filepath.Join(configDir(), "trusted", "*"))
	var out []string
	for _, f := range files {
		if b, err := os.ReadFile(f); err == nil {
			if p, _, ok := strings.Cut(string(b), "\n"); ok && filepath.IsAbs(p) {
				out = append(out, p)
			}
		}
	}
	return out
}

// normalize validates a rule and returns its canonical stored form.
func normalize(kind, pattern string) (string, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || strings.IndexFunc(pattern, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("empty or invalid rule")
	}
	switch kind {
	case "read", "write":
		if pattern == "~" || strings.HasPrefix(pattern, "~/") {
			pattern = home() + pattern[1:]
		}
		if !strings.HasPrefix(pattern, "/") {
			return "", fmt.Errorf("path rules must be absolute: %q", pattern)
		}
		if strings.HasSuffix(pattern, "/**") {
			pattern += "*"
		}
		if pattern != "/" {
			pattern = strings.TrimSuffix(pattern, "/")
		}
	case "hosts":
		pattern = strings.ToLower(pattern)
		if strings.ContainsAny(pattern, "/ @") {
			return "", fmt.Errorf("hosts are domain globs like *.github.com, not URLs")
		}
	case "connect":
		if strings.ContainsAny(pattern, " \t") {
			return "", fmt.Errorf("invalid connect target")
		}
	case "ignore":
		if strings.HasPrefix(pattern, "~/") {
			pattern = home() + pattern[1:]
		}
	default:
		return "", fmt.Errorf("unknown rule kind %q", kind)
	}
	return pattern, nil
}

// Protected paths are denied after every grant, so no rule can override them.
// noAccess blocks read+write; noWrite blocks writes (the project's own rules
// file, and things that later run outside the sandbox, e.g. shell rc files).
func protected(project string) (noAccess, noWrite []string) {
	h := home()
	noAccess = []string{configDir(), stateDir(), filepath.Join(h, ".ssh"), filepath.Join(h, ".gnupg")}
	noWrite = []string{filepath.Join(h, ".local", "bin"), filepath.Join(h, ".bashrc"), filepath.Join(h, ".bash_profile"),
		filepath.Join(h, ".profile"), filepath.Join(h, ".zshrc"), filepath.Join(h, ".zprofile"), filepath.Join(h, ".zshenv"),
		filepath.Join(h, ".config", "systemd"), filepath.Join(h, ".config", "autostart")}
	if exe, err := os.Executable(); err == nil {
		noWrite = append(noWrite, exe)
	}
	if project != "" {
		noWrite = append(noWrite, filepath.Join(project, projectFile), filepath.Join(project, projectFile+".tmp"),
			filepath.Join(project, ".git", "hooks"), filepath.Join(project, ".git", "config"))
	}
	return
}

func protectionCommands(project string) []string {
	var lines []string
	noAccess, noWrite := protected(project)
	for _, x := range noAccess {
		lines = append(lines, "deny/all+"+x, "deny/all+"+x+"/***")
	}
	for _, x := range noWrite {
		lines = append(lines, "deny/"+writeCaps+"+"+x, "deny/"+writeCaps+"+"+x+"/***")
	}
	return lines
}

func under(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/")
}

// overlaps reports whether pattern could match protected path x or anything below it.
func overlaps(pattern, x string) bool {
	lit := pattern
	if i := strings.IndexAny(pattern, "*?["); i >= 0 {
		lit = pattern[:i]
		if j := strings.LastIndex(lit, "/"); j >= 0 {
			lit = lit[:j]
		}
		if lit == "" {
			lit = "/"
		}
		return under(lit, x) || under(x, lit)
	}
	return under(lit, x)
}

func checkProtected(project, kind, pattern string) error {
	noAccess, noWrite := protected(project)
	for _, x := range noAccess {
		if overlaps(pattern, x) {
			return fmt.Errorf("%s overlaps protected path %s", pattern, x)
		}
	}
	if kind == "write" {
		for _, x := range noWrite {
			if overlaps(pattern, x) {
				return fmt.Errorf("%s overlaps write-protected path %s", pattern, x)
			}
		}
	}
	return nil
}

// globRegexp converts a path rule (Syd glob semantics) to a regexp.
func globRegexp(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); {
		switch {
		case strings.HasPrefix(pattern[i:], "/***"):
			b.WriteString("(/.*)?")
			i += 4
		case strings.HasPrefix(pattern[i:], "**"):
			b.WriteString(".*")
			i += 2
		case pattern[i] == '*':
			b.WriteString("[^/]*")
			i++
		case pattern[i] == '?':
			b.WriteString("[^/]")
			i++
		default:
			b.WriteString(regexp.QuoteMeta(pattern[i : i+1]))
			i++
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return regexp.MustCompile("^$")
	}
	return re
}

func matchPath(pattern, p string) bool { return globRegexp(pattern).MatchString(p) }

// matchHost: "*.x.com" matches subdomains, "*" matches all, optional ":port".
func matchHost(pattern, host, port string) bool {
	if h, p, ok := strings.Cut(pattern, ":"); ok {
		if p != port {
			return false
		}
		pattern = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	switch {
	case pattern == "*":
		return true
	case strings.HasPrefix(pattern, "*."):
		return strings.HasSuffix(host, pattern[1:])
	}
	return host == pattern
}

// Syd capability sets for each rule kind. write implies read.
const (
	readCaps  = "read,readdir,readlink,chdir,stat,exec"
	writeCaps = "all"
)

func ignored(r []Rules, kind, target string) bool {
	for _, rules := range r {
		for _, p := range rules.Ignore {
			if kind == "hosts" {
				h, port, _ := strings.Cut(target, ":")
				if matchHost(p, h, port) {
					return true
				}
			} else if p == target || (strings.HasPrefix(p, "/") && matchPath(p, target)) {
				return true
			}
		}
	}
	return false
}

// sydCommands turns a rule into the Syd commands that grant (op "+") or
// revoke (op "-") it. Hosts are enforced by the proxy, not Syd.
func sydCommands(kind, pattern, op string) []string {
	switch kind {
	case "read":
		return []string{"allow/" + readCaps + op + pattern}
	case "write":
		return []string{"allow/" + writeCaps + op + pattern}
	case "connect":
		return []string{"allow/net/connect" + op + pattern}
	}
	return nil
}

// compileProfile builds the Syd profile for one session.
func compileProfile(project string, rules []Rules, proxyPort int, ipc string, learn bool) string {
	h := home()
	lines := []string{
		"# generated by sydguard; edit rules in " + configDir(),
		"sandbox/lock:off", "sandbox/fs:off", "sandbox/ioctl:off", "sandbox/stat:off",
		"trace/allow_unsafe_exec_nopie:1",
		"allow/create+!*", "allow/net/bind+!unnamed",
		"allow/net/bind+127.0.0.1!0-65535", "allow/net/bind+::1!0-65535",
		fmt.Sprintf("allow/net/connect+127.0.0.1!%d", proxyPort),
		"allow/read,readdir,chdir+/",
	}
	if learn {
		lines = append(lines, "default/all:warn", "default/net:warn")
	}
	// Syd strips proxy variables from the agent's environment unless passed.
	lines = append(lines, "passenv+*_PROXY", "passenv+*_proxy")
	for _, p := range []string{"/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/opt", "/proc", "/sys", "/dev", "/run/systemd/resolve", "/snap"} {
		lines = append(lines, "allow/"+readCaps+"+"+p+"/***")
	}
	lines = append(lines, "allow/chdir,readlink+"+h)
	for _, p := range []string{project + "/***", "/tmp/***", "/var/tmp/***", "/dev/shm/***", "/dev/pts/***", "/dev/null", "/dev/zero", "/dev/tty", "/dev/ptmx", "/dev/full"} {
		lines = append(lines, "allow/"+writeCaps+"+"+p)
	}
	for _, r := range rules {
		for _, k := range kinds {
			for _, pat := range *r.list(k) {
				if k == "read" || k == "write" {
					if norm, err := normalize(k, pat); err == nil {
						pat = norm
					} else {
						continue
					}
				}
				lines = append(lines, sydCommands(k, pat, "+")...)
			}
		}
	}
	lines = append(lines, protectionCommands(project)...)
	lines = append(lines, "ipc:"+ipc, "lock:ipc")
	return strings.Join(lines, "\n") + "\n"
}

// suggestions offers the exact path plus parent directories (stopping above
// home or two levels below /).
func suggestions(p string, dir bool) []string {
	var out []string
	if dir {
		out = append(out, p+"/***")
	} else {
		out = append(out, p)
	}
	h := home()
	for d := filepath.Dir(p); d != "/" && strings.Count(d, "/") >= 2 && d != h && len(out) < 5; d = filepath.Dir(d) {
		out = append(out, d+"/***")
	}
	return slices.Compact(out)
}

func hostSuggestions(host string) []string {
	out := []string{host}
	parts := strings.Split(host, ".")
	for i := 1; i < len(parts)-1; i++ {
		out = append(out, "*."+strings.Join(parts[i:], "."))
	}
	return out
}
