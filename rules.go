package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// Rules is the whole user-facing policy language.
//
//	read/write: path globs. "*" = one path segment, "**" = anything,
//	            "/dir/**" (Syd: "/dir/***") = dir and everything below. "~/" ok.
//	hosts:      [protocol://]host[:port] for the HTTP(S) proxy, by NAME never IP:
//	            "github.com" (any port/protocol), "https://github.com" (443),
//	            "*.github.com" (subdomains), "tcp://db.example.com:5432".
//	connect:    raw Syd network targets for tools that ignore the proxy, e.g.
//	            "140.82.112.3!22" or "/run/user/1000/bus". Advanced; prefer hosts.
//	ignore:     path or host globs that stay denied without asking again.
type Rules struct {
	Read    []string `json:"read,omitempty"`
	Write   []string `json:"write,omitempty"`
	Hosts   []string `json:"hosts,omitempty"`
	Connect []string `json:"connect,omitempty"`
	Ignore  []string `json:"ignore,omitempty"`
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

func (r Rules) clone() Rules {
	c := Rules{}
	for _, k := range kinds {
		*c.list(k) = slices.Clone(*r.list(k))
	}
	return c
}

func home() string { h, _ := os.UserHomeDir(); return h }

func configDir() string { return filepath.Join(home(), ".config", "sydguard") }
func stateDir() string  { return filepath.Join(home(), ".local", "state", "sydguard") }

// safeText rejects anything that could break out of a single Syd command line.
func safeText(s string) error {
	if s == "" || len(s) > 4096 || strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) || r == unicode.ReplacementChar }) >= 0 {
		return fmt.Errorf("invalid text %q", s)
	}
	return nil
}

// safePath is safeText plus: absolute, no "..".
func safePath(p string) error {
	if err := safeText(p); err != nil {
		return err
	}
	if !filepath.IsAbs(p) || slices.Contains(strings.Split(p, "/"), "..") {
		return fmt.Errorf("path must be absolute without '..': %q", p)
	}
	return nil
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		return home() + p[1:]
	}
	return p
}

// normalize validates a rule and returns its canonical stored form.
func normalize(kind, pattern string) (string, error) {
	pattern = strings.TrimSpace(pattern)
	if err := safeText(pattern); err != nil {
		return "", err
	}
	switch kind {
	case "read", "write":
		pattern = expandHome(pattern)
		if strings.HasSuffix(pattern, "/**") {
			pattern += "*"
		}
		if len(pattern) > 1 {
			pattern = strings.TrimSuffix(pattern, "/")
		}
		if err := safePath(pattern); err != nil {
			return "", err
		}
		if strings.Contains(pattern, "//") {
			return "", fmt.Errorf("invalid path %q", pattern)
		}
	case "hosts":
		h, err := parseHostRule(pattern)
		if err != nil {
			return "", err
		}
		pattern = h.String()
	case "connect":
		if strings.ContainsAny(pattern, " ") {
			return "", fmt.Errorf("invalid connect target %q", pattern)
		}
		if strings.HasPrefix(pattern, "/") {
			if err := safePath(pattern); err != nil {
				return "", err
			}
		}
	case "ignore":
		pattern = expandHome(pattern)
	default:
		return "", fmt.Errorf("unknown rule kind %q", kind)
	}
	return pattern, nil
}

// Host rules ---------------------------------------------------------------

type hostRule struct {
	Scheme string // "", http, https, tcp
	Host   string // lowercase name or glob ("*", "*.x.com")
	Port   string // "" = default for scheme, or any when no scheme
}

var hostRe = regexp.MustCompile(`^(\*|(\*\.)?[a-z0-9_]([a-z0-9_-]*[a-z0-9])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9])?)*\.?|\[[0-9a-f:.]+\])$`)

func parseHostRule(s string) (hostRule, error) {
	var h hostRule
	s = strings.ToLower(strings.TrimSpace(s))
	if scheme, rest, ok := strings.Cut(s, "://"); ok {
		if scheme != "http" && scheme != "https" && scheme != "tcp" {
			return h, fmt.Errorf("protocol must be http, https or tcp: %q", s)
		}
		h.Scheme, s = scheme, rest
	}
	s = strings.TrimSuffix(s, "/")
	if strings.ContainsAny(s, "/?#@ ") {
		return h, fmt.Errorf("host rules are [protocol://]host[:port], not URLs: %q", s)
	}
	host, port := s, ""
	if i := strings.LastIndex(s, ":"); i >= 0 && !strings.HasSuffix(s, "]") {
		host, port = s[:i], s[i+1:]
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return h, fmt.Errorf("bad port in %q", s)
		}
	}
	if !hostRe.MatchString(host) {
		return h, fmt.Errorf("bad host %q", host)
	}
	h.Host, h.Port = strings.TrimSuffix(host, "."), port
	return h, nil
}

func (h hostRule) String() string {
	s := h.Host
	if h.Port != "" {
		s += ":" + h.Port
	}
	if h.Scheme != "" {
		s = h.Scheme + "://" + s
	}
	return s
}

func defaultPort(scheme string) string {
	return map[string]string{"http": "80", "https": "443"}[scheme]
}

// match: scheme is "http" for plain proxied requests, "https"/"tcp" for CONNECT.
func (h hostRule) match(scheme, host, port string) bool {
	switch h.Scheme {
	case "":
	case "tcp":
		if scheme == "http" {
			return false
		}
	default:
		if h.Scheme != scheme {
			return false
		}
	}
	want := h.Port
	if want == "" {
		want = defaultPort(h.Scheme)
	}
	if want != "" && want != port {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	switch {
	case h.Host == "*":
		return true
	case strings.HasPrefix(h.Host, "*."):
		return strings.HasSuffix(host, h.Host[1:])
	}
	return host == strings.Trim(h.Host, "[]")
}

// exact: no wildcard and an explicit or implied port. Only exact rules may
// reach private (LAN/VPN/host) addresses.
func (h hostRule) exact() bool {
	return !strings.Contains(h.Host, "*") && (h.Port != "" || h.Scheme == "http" || h.Scheme == "https")
}

func connectScheme(port string) string {
	if port == "443" {
		return "https"
	}
	return "tcp"
}

func hostSuggestions(scheme, host, port string) []string {
	first := scheme + "://" + host
	if port != defaultPort(scheme) {
		first += ":" + port
	}
	out := []string{first, host}
	parts := strings.Split(host, ".")
	for i := 1; i < len(parts)-1; i++ {
		out = append(out, "*."+strings.Join(parts[i:], "."))
	}
	return out
}

// Paths -------------------------------------------------------------------

func under(p, dir string) bool {
	return p == dir || dir == "/" || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/")
}

// literalPrefix is the directory part of a pattern before its first wildcard.
func literalPrefix(pattern string) string {
	i := strings.IndexAny(pattern, "*?[")
	if i < 0 {
		return pattern
	}
	lit := pattern[:i]
	if j := strings.LastIndex(lit, "/"); j > 0 {
		return lit[:j]
	}
	return "/"
}

// overlaps reports whether pattern could match protected path x or anything
// below it. Conservative: may refuse some harmless patterns, never misses.
func overlaps(pattern, x string) bool {
	lit := literalPrefix(pattern)
	if lit == pattern {
		return under(lit, x)
	}
	return under(lit, x) || under(x, lit)
}

// Protected paths are always denied (and re-denied in every live update).
// noAccess: no read or write. noWrite: readable, never modifiable.
type protection struct{ noAccess, noWrite []string }

func protectedFor(project string, rulesFiles ...string) protection {
	h := home()
	p := protection{
		noAccess: []string{configDir(), stateDir(), filepath.Join(h, ".ssh"), filepath.Join(h, ".gnupg"), filepath.Join(h, ".lima")},
		noWrite: []string{filepath.Join(h, ".local", "bin"), filepath.Join(h, ".bashrc"), filepath.Join(h, ".bash_profile"),
			filepath.Join(h, ".profile"), filepath.Join(h, ".zshrc"), filepath.Join(h, ".zprofile"), filepath.Join(h, ".zshenv"),
			filepath.Join(h, ".config", "systemd"), filepath.Join(h, ".config", "autostart")},
	}
	if exe, err := os.Executable(); err == nil {
		p.noWrite = append(p.noWrite, exe)
	}
	if project != "" {
		p.noWrite = append(p.noWrite, filepath.Join(project, defaultRulesName), filepath.Join(project, defaultRulesName+".tmp"),
			filepath.Join(project, rulesDirName), filepath.Join(project, ".git", "hooks"), filepath.Join(project, ".git", "config"))
	}
	for _, f := range rulesFiles {
		if f != "" {
			p.noWrite = append(p.noWrite, f, f+".tmp")
		}
	}
	return p
}

func (p protection) check(kind, pattern string) error {
	if kind != "read" && kind != "write" {
		return nil
	}
	for _, x := range p.noAccess {
		if overlaps(pattern, x) {
			return fmt.Errorf("%s overlaps protected %s", pattern, x)
		}
	}
	if kind == "write" {
		for _, x := range p.noWrite {
			if overlaps(pattern, x) {
				return fmt.Errorf("%s overlaps write-protected %s", pattern, x)
			}
		}
	}
	return nil
}

func (p protection) commands() []string {
	var lines []string
	for _, x := range p.noAccess {
		lines = append(lines, "deny/"+writeCaps+"+"+x, "deny/"+writeCaps+"+"+x+"/***")
	}
	for _, x := range p.noWrite {
		lines = append(lines, "deny/"+modifyCaps+"+"+x, "deny/"+modifyCaps+"+"+x+"/***")
	}
	return lines
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

// Syd capabilities. "write" in a rule means read + modify, not Syd's "all".
const (
	readCaps   = "read,readdir,readlink,chdir,stat,exec"
	modifyCaps = "write,create,delete,rename,truncate,symlink,chmod,chattr,chown,chgrp,utime,mkdir,rmdir,mkfifo,mktemp"
	writeCaps  = readCaps + "," + modifyCaps
)

// sydCommands turns a rule into the Syd commands that grant (op "+") or
// revoke (op "-") it. Hosts and ignores are enforced by sydguard, not Syd.
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

// Baseline: what every session gets without any rules. Shown in the UI.
type baseRule struct {
	Kind    string `json:"kind"`
	Pattern string `json:"pattern"`
	Why     string `json:"why"`
}

func baseline(project string) []baseRule {
	var out []baseRule
	for _, p := range []string{"/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/opt", "/proc", "/sys", "/dev", "/run/systemd/resolve", "/snap"} {
		out = append(out, baseRule{"read", p + "/***", "system"})
	}
	out = append(out, baseRule{"write", project + "/***", "the project (git root)"})
	for _, p := range []string{"/tmp/***", "/var/tmp/***", "/dev/shm/***"} {
		out = append(out, baseRule{"write", p, "temporary files"})
	}
	return out
}

type profileInput struct {
	Project   string
	Rules     []Rules
	Launch    []string
	Protect   protection
	ProxyPort int
	IPC       string
	Learn     bool
}

// compileProfile builds the Syd profile for one session.
func compileProfile(in profileInput) (string, error) {
	if err := safePath(in.Project); err != nil {
		return "", err
	}
	if err := safeText(in.IPC); err != nil {
		return "", err
	}
	lines := []string{
		"# generated by sydguard",
		// Landlock off: live grants may go anywhere you approve (no fixed kernel
		// ceiling). Syd still enforces every path rule via seccomp-unotify.
		"sandbox/lock:off", "sandbox/fs:off", "sandbox/ioctl:off", "sandbox/stat:off",
		// Agents run from ~/.local/bin, ~/.pi, pnpm (group-writable dirs under
		// Ubuntu's umask, symlink-heavy) and use JITs (node, bun).
		"sandbox/tpe:off", "trace/allow_unsafe_symlinks:1", "trace/allow_unsafe_exec_nopie:1", "trace/allow_unsafe_exec_memory:1",
		"passenv+*_PROXY", "passenv+*_proxy",
		"allow/create+!*", "allow/net/bind+!unnamed",
		"allow/net/bind+127.0.0.1!0-65535", "allow/net/bind+::1!0-65535",
		fmt.Sprintf("allow/net/connect+127.0.0.1!%d", in.ProxyPort),
		"allow/read,readdir,chdir+/", "allow/chdir,readlink+" + home(),
	}
	if in.Learn {
		lines = append(lines, "default/all:warn", "default/net:warn")
	}
	for _, b := range baseline(in.Project) {
		lines = append(lines, sydCommands(b.Kind, b.Pattern, "+")...)
	}
	for _, p := range []string{"/dev/null", "/dev/zero", "/dev/full", "/dev/tty", "/dev/ptmx", "/dev/pts/***"} {
		lines = append(lines, sydCommands("write", p, "+")...)
	}
	for _, p := range in.Launch {
		if safePath(p) == nil && in.Protect.check("read", p) == nil {
			lines = append(lines, sydCommands("read", p, "+")...)
		}
	}
	for _, r := range in.Rules {
		for _, k := range []string{"read", "write", "connect"} {
			for _, pat := range *r.list(k) {
				norm, err := normalize(k, pat)
				if err != nil || in.Protect.check(k, norm) != nil {
					continue // invalid or unsafe rules never reach Syd
				}
				lines = append(lines, sydCommands(k, norm, "+")...)
			}
		}
	}
	lines = append(lines, in.Protect.commands()...)
	lines = append(lines, "ipc:"+in.IPC, "lock:ipc")
	return strings.Join(lines, "\n") + "\n", nil
}

// suggestions: the exact path first, then parents (not above home).
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

// learnRoot collapses a path to the folder a person would approve:
// ~/.pi/agent/x -> ~/.pi, ~/.local/share/pnpm/store/... -> ~/.local/share/pnpm,
// ~/.config/gh/x -> ~/.config/gh, elsewhere -> the file's directory.
func learnRoot(p string) string {
	h := home()
	if !under(p, h) || p == h {
		if d := filepath.Dir(p); d != "/" {
			return d
		}
		return p
	}
	parts := strings.Split(strings.TrimPrefix(p, h+"/"), "/")
	n := 1
	switch {
	case len(parts) >= 2 && (parts[0] == ".config" || parts[0] == ".cache"):
		n = 2
	case len(parts) >= 3 && parts[0] == ".local" && (parts[1] == "share" || parts[1] == "state" || parts[1] == "lib"):
		n = 3
	}
	if len(parts) <= n && !strings.HasPrefix(parts[0], ".") {
		return filepath.Dir(p)
	}
	if len(parts) < n {
		n = len(parts)
	}
	return filepath.Join(append([]string{h}, parts[:n]...)...)
}

// hostOf strips protocol and port from a host card target.
func hostOf(target string) string {
	if _, rest, ok := strings.Cut(target, "://"); ok {
		target = rest
	}
	if i := strings.LastIndex(target, ":"); i >= 0 && !strings.HasSuffix(target, "]") {
		target = target[:i]
	}
	return target
}

func ignored(r []Rules, kind, target string) bool {
	for _, rules := range r {
		for _, p := range rules.Ignore {
			if kind == "hosts" {
				host := hostOf(target)
				if h, err := parseHostRule(p); err == nil && (h.Host == host || h.Host == "*" || (strings.HasPrefix(h.Host, "*.") && strings.HasSuffix(host, h.Host[1:]))) {
					return true
				}
			} else if p == target || (strings.HasPrefix(p, "/") && matchPath(p, target)) {
				return true
			}
		}
	}
	return false
}
