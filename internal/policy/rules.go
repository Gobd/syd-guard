// Package policy is the rules language and how it maps onto Syd.
package policy

import (
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Gobd/syd-guard/internal/system"
)

// Rules is the whole user-facing policy language.
//
//	read/write: path globs. "*" = one path segment, "**" = anything,
//	            "/dir/**" (Syd: "/dir/***") = dir and everything below. "~/" ok.
//	hosts:      [protocol://]host[:port] for the per-session network, by NAME:
//	            "github.com" (any port/protocol), "https://github.com" (443),
//	            "*.github.com" (subdomains), "tcp://db.example.com:5432", "udp://dns:53".
//	connect:    raw Syd network targets for tools that ignore the proxy, e.g.
//	            "140.82.112.3!22" or "/run/user/1000/bus". Advanced; prefer hosts.
//	ignore:     path or host globs that stay denied without asking again.
type Rules struct {
	Read    []string `json:"read,omitempty"`
	Write   []string `json:"write,omitempty"`
	Hosts   []string `json:"hosts,omitempty"`
	Connect []string `json:"connect,omitempty"`
	Ignore  []string `json:"ignore,omitempty"`
	// Commands this project's agents may ask sydguard to run on the host
	// (`sydguard cmd NAME`). Approved once per definition on the host.
	Commands map[string]Command `json:"commands,omitempty"`
}

var Kinds = []string{"read", "write", "hosts", "connect", "ignore"}

func (r *Rules) List(kind string) *[]string {
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

func (r Rules) Clone() Rules {
	c := Rules{}
	for _, k := range Kinds {
		*c.List(k) = slices.Clone(*r.List(k))
	}
	if r.Commands != nil {
		c.Commands = map[string]Command{}
		for name, cmd := range r.Commands {
			cmd.Run = slices.Clone(cmd.Run)
			cmd.Args = maps.Clone(cmd.Args)
			c.Commands[name] = cmd
		}
	}
	return c
}

// Normalize validates a rule and returns its canonical stored form.
func Normalize(kind, pattern string) (string, error) {
	pattern = strings.TrimSpace(pattern)
	if err := system.SafeText(pattern); err != nil {
		return "", err
	}
	switch kind {
	case "read", "write":
		pattern = system.ExpandHome(pattern)
		if strings.HasSuffix(pattern, "/**") {
			pattern += "*"
		}
		if len(pattern) > 1 {
			pattern = strings.TrimSuffix(pattern, "/")
		}
		if err := system.SafePath(pattern); err != nil {
			return "", err
		}
		if strings.Contains(pattern, "//") {
			return "", fmt.Errorf("invalid path %q", pattern)
		}
	case "hosts":
		h, err := ParseHostRule(pattern)
		if err != nil {
			return "", err
		}
		pattern = h.String()
	case "connect":
		if strings.ContainsAny(pattern, " ") {
			return "", fmt.Errorf("invalid connect target %q", pattern)
		}
		if strings.HasPrefix(pattern, "/") {
			if err := system.SafePath(pattern); err != nil {
				return "", err
			}
		}
	case "ignore":
		pattern = system.ExpandHome(pattern)
	default:
		return "", fmt.Errorf("unknown rule kind %q", kind)
	}
	return pattern, nil
}

// Host rules ---------------------------------------------------------------

type HostRule struct {
	Scheme string // "", http, https, tcp, udp
	Host   string // lowercase name or glob ("*", "*.x.com")
	Port   string // "" = default for scheme, or any when no scheme
}

var hostRe = regexp.MustCompile(`^(\*|(\*\.)?[a-z0-9_]([a-z0-9_-]*[a-z0-9])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9])?)*\.?|\[[0-9a-f:.]+\])$`)

func ParseHostRule(s string) (HostRule, error) {
	var h HostRule
	s = strings.ToLower(strings.TrimSpace(s))
	if scheme, rest, ok := strings.Cut(s, "://"); ok {
		if scheme != "http" && scheme != "https" && scheme != "tcp" && scheme != "udp" {
			return h, fmt.Errorf("protocol must be http, https, tcp or udp: %q", s)
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

func (h HostRule) String() string {
	s := h.Host
	if h.Port != "" {
		s += ":" + h.Port
	}
	if h.Scheme != "" {
		s = h.Scheme + "://" + s
	}
	return s
}

func DefaultPort(scheme string) string {
	return map[string]string{"http": "80", "https": "443"}[scheme]
}

// match: scheme is "http" for plain proxied requests, "https"/"tcp" for CONNECT.
func (h HostRule) Match(scheme, host, port string) bool {
	switch h.Scheme {
	case "":
	case "tcp":
		if scheme != "tcp" && scheme != "https" {
			return false
		}
	default:
		if h.Scheme != scheme {
			return false
		}
	}
	want := h.Port
	if want == "" {
		want = DefaultPort(h.Scheme)
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
// MatchName matches the host part only (for DNS, where there's no port yet).
func (h HostRule) MatchName(host string) bool {
	return HostRule{Host: h.Host}.Match("", host, "")
}

// PortRange is the Syd port spec this rule allows for raw connections.
func (h HostRule) PortRange() string {
	if h.Port != "" {
		return h.Port
	}
	if p := DefaultPort(h.Scheme); p != "" {
		return p
	}
	return "0-65535"
}

func (h HostRule) Exact() bool {
	return !strings.Contains(h.Host, "*") && (h.Port != "" || h.Scheme == "http" || h.Scheme == "https")
}

func ConnectScheme(port string) string {
	if port == "443" {
		return "https"
	}
	return "tcp"
}

func HostSuggestions(scheme, host, port string) []string {
	var out []string
	if scheme != "" {
		first := scheme + "://" + host
		if port != DefaultPort(scheme) {
			first += ":" + port
		}
		out = append(out, first)
	}
	out = append(out, host)
	parts := strings.Split(host, ".")
	for i := 1; i < len(parts)-1; i++ {
		out = append(out, "*."+strings.Join(parts[i:], "."))
	}
	return out
}

// Paths -------------------------------------------------------------------

// LiteralPrefix is the directory part of a pattern before its first wildcard.
func LiteralPrefix(pattern string) string {
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

// Overlaps reports whether pattern could match protected path x or anything
// below it. Conservative: may refuse some harmless patterns, never misses.
func Overlaps(pattern, x string) bool {
	lit := LiteralPrefix(pattern)
	if lit == pattern {
		return system.Under(lit, x)
	}
	return system.Under(lit, x) || system.Under(x, lit)
}

// Protected paths are always denied (and re-denied in every live update).
// NoAccess: no read or write. NoWrite: readable, never modifiable.
type Protection struct{ NoAccess, NoWrite []string }

func ProtectedFor(project string, rulesFiles ...string) Protection {
	h := system.Home()
	p := Protection{
		NoAccess: []string{system.ConfigDir(), system.StateDir(), filepath.Join(h, ".ssh"), filepath.Join(h, ".gnupg"), filepath.Join(h, ".lima")},
		NoWrite: []string{
			filepath.Join(h, ".local", "bin"), filepath.Join(h, ".bashrc"), filepath.Join(h, ".bash_profile"),
			filepath.Join(h, ".profile"), filepath.Join(h, ".zshrc"), filepath.Join(h, ".zprofile"), filepath.Join(h, ".zshenv"),
			filepath.Join(h, ".config", "systemd"), filepath.Join(h, ".config", "autostart"),
		},
	}
	if exe, err := os.Executable(); err == nil {
		p.NoWrite = append(p.NoWrite, exe)
	}
	if project != "" {
		p.NoWrite = append(p.NoWrite, filepath.Join(project, DefaultRulesName), filepath.Join(project, DefaultRulesName+".tmp"),
			filepath.Join(project, RulesDirName), filepath.Join(project, ".git", "hooks"), filepath.Join(project, ".git", "config"))
	}
	for _, f := range rulesFiles {
		if f != "" {
			p.NoWrite = append(p.NoWrite, f, f+".tmp")
		}
	}
	return p
}

func (p Protection) Check(kind, pattern string) error {
	if kind != "read" && kind != "write" {
		return nil
	}
	for _, x := range p.NoAccess {
		if Overlaps(pattern, x) {
			return fmt.Errorf("%s Overlaps protected %s", pattern, x)
		}
	}
	if kind == "write" {
		for _, x := range p.NoWrite {
			if Overlaps(pattern, x) {
				return fmt.Errorf("%s Overlaps write-protected %s", pattern, x)
			}
		}
	}
	return nil
}

func (p Protection) Commands() []string {
	var lines []string
	for _, x := range p.NoAccess {
		lines = append(lines, "deny/"+WriteCaps+"+"+x, "deny/"+WriteCaps+"+"+x+"/***")
	}
	for _, x := range p.NoWrite {
		lines = append(lines, "deny/"+ModifyCaps+"+"+x, "deny/"+ModifyCaps+"+"+x+"/***")
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

func MatchPath(pattern, p string) bool { return globRegexp(pattern).MatchString(p) }

// Syd capabilities. "write" in a rule means read + modify, not Syd's "all".
const (
	ReadCaps   = "read,readdir,readlink,chdir,stat,exec"
	ModifyCaps = "write,create,delete,rename,truncate,symlink,chmod,chattr,chown,chgrp,utime,mkdir,rmdir,mkfifo,mktemp"
	WriteCaps  = ReadCaps + "," + ModifyCaps
)

// SydCommands turns a rule into the Syd commands that grant (op "+") or
// revoke (op "-") it. Hosts and ignores are enforced by sydguard, not Syd.
func SydCommands(kind, pattern, op string) []string {
	switch kind {
	case "read":
		return []string{"allow/" + ReadCaps + op + pattern}
	case "write":
		return []string{"allow/" + WriteCaps + op + pattern}
	case "connect":
		return []string{"allow/net/connect" + op + pattern}
	}
	return nil
}

// Baseline: what every session gets without any rules. Shown in the UI.
type BaseRule struct {
	Kind    string `json:"kind"`
	Pattern string `json:"pattern"`
	Why     string `json:"why"`
}

func Baseline(project string) []BaseRule {
	var out []BaseRule
	for _, p := range []string{"/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/opt", "/proc", "/sys", "/dev", "/run/systemd/resolve", "/snap"} {
		out = append(out, BaseRule{"read", p + "/***", "system"})
	}
	out = append(out, BaseRule{"write", project + "/***", "the folder sydguard was launched in"})
	for _, p := range []string{"/tmp/***", "/var/tmp/***", "/dev/shm/***"} {
		out = append(out, BaseRule{"write", p, "temporary files"})
	}
	return out
}

// Overlay bind-mounts a VM-local folder over a project folder (e.g. node_modules).
type Overlay struct{ Source, Target string }

type ProfileInput struct {
	Network    bool   // private user/mount/net namespace with daemon-owned TUN
	DNS        string // session resolver address
	ResolvConf string // file bind-mounted over /etc/resolv.conf
	Overlays   []Overlay
	LocalPorts []int    // loopback ports of trusted helpers the agent may use
	PassEnv    []string // env var names to keep (Syd strips some by default)
	Project    string
	Rules      []Rules
	Launch     []string
	Protect    Protection
	ProxyPort  int
	IPC        string
	Learn      bool
}

// CompileProfile builds the Syd profile for one session.
func CompileProfile(in ProfileInput) (string, error) {
	if err := system.SafePath(in.Project); err != nil {
		return "", err
	}
	if err := system.SafeText(in.IPC); err != nil {
		return "", err
	}
	lines := []string{
		"# generated by sydguard",
		// Landlock off: live grants may go anywhere you approve (no fixed kernel
		// ceiling). Syd still enforces every path rule via seccomp-unotify.
		"sandbox/lock:off", "sandbox/fs:off", "sandbox/ioctl:off", "sandbox/stat:off",
		// Agents run from ~/.local/bin, ~/.pi, pnpm (group-writable dirs system.Under
		// Ubuntu's umask, symlink-heavy) and use JITs (node, bun).
		"sandbox/tpe:off", "trace/allow_unsafe_symlinks:1", "trace/allow_unsafe_exec_nopie:1", "trace/allow_unsafe_exec_memory:1",
		// Ubuntu's umask makes files group-writable; Syd's "trusted file creation"
		// would then refuse `> existing-file`. That guards shared multi-user
		// directories, not a single-user VM.
		"trace/allow_unsafe_create:1",
		"passenv+*_PROXY", "passenv+*_proxy",
		"allow/create+!*", "allow/net/bind+!unnamed",
		"allow/net/bind+127.0.0.1!0-65535", "allow/net/bind+::1!0-65535",
		fmt.Sprintf("allow/net/connect+127.0.0.1!%d", in.ProxyPort),
		"allow/read,readdir,chdir+/", "allow/chdir,readlink+" + system.Home(),
	}
	if in.Network || in.DNS != "" || len(in.Overlays) > 0 {
		lines = append(lines, "unshare/user:1", "unshare/mount:1")
	}
	if in.Network {
		// IP sockets stay within the namespace. Only the daemon can relay
		// them to the host; keep Syd's Unix-socket policy intact.
		lines = append(lines, "unshare/net:1", "root/map:1", "allow/net/connect+0.0.0.0/0!0-65535", "allow/net/connect+::/0!0-65535")
	}
	if in.DNS != "" {
		host, _, err := net.SplitHostPort(in.DNS)
		if err != nil || system.SafePath(in.ResolvConf) != nil || strings.Contains(in.ResolvConf, ":") {
			return "", fmt.Errorf("bad dns config")
		}
		lines = append(lines, "bind+"+in.ResolvConf+":/etc/resolv.conf:ro", "allow/net/connect+"+host+"!53")
	}
	for _, o := range in.Overlays {
		if system.SafePath(o.Source) != nil || system.SafePath(o.Target) != nil || strings.Contains(o.Source+o.Target, ":") {
			return "", fmt.Errorf("bad overlay %q", o.Target)
		}
		lines = append(lines, "bind+"+o.Source+":"+o.Target)
	}
	for _, p := range in.LocalPorts {
		if p < 1 || p > 65535 {
			return "", fmt.Errorf("bad local port %d", p)
		}
		lines = append(lines, fmt.Sprintf("allow/net/connect+127.0.0.1!%d", p))
	}
	for _, name := range in.PassEnv {
		if system.SafeText(name) != nil || strings.ContainsAny(name, " =*?[") {
			return "", fmt.Errorf("bad env name %q", name)
		}
		lines = append(lines, "passenv+"+name)
	}
	if in.Learn {
		lines = append(lines, "default/all:warn", "default/net:warn")
	}
	for _, b := range Baseline(in.Project) {
		lines = append(lines, SydCommands(b.Kind, b.Pattern, "+")...)
	}
	for _, p := range []string{"/dev/null", "/dev/zero", "/dev/full", "/dev/tty", "/dev/ptmx", "/dev/pts/***"} {
		lines = append(lines, SydCommands("write", p, "+")...)
	}
	for _, p := range in.Launch {
		if system.SafePath(p) == nil && in.Protect.Check("read", p) == nil {
			lines = append(lines, SydCommands("read", p, "+")...)
		}
	}
	for _, r := range in.Rules {
		for _, k := range []string{"read", "write", "connect"} {
			for _, pat := range *r.List(k) {
				norm, err := Normalize(k, pat)
				if err != nil || in.Protect.Check(k, norm) != nil {
					continue // invalid or unsafe rules never reach Syd
				}
				lines = append(lines, SydCommands(k, norm, "+")...)
			}
		}
	}
	lines = append(lines, in.Protect.Commands()...)
	lines = append(lines, "ipc:"+in.IPC, "lock:ipc")
	return strings.Join(lines, "\n") + "\n", nil
}

// Suggestions: the exact path first, then parents (not above home).
func Suggestions(p string, dir bool) []string {
	var out []string
	if dir {
		out = append(out, p+"/***")
	} else {
		out = append(out, p)
	}
	h := system.Home()
	for d := filepath.Dir(p); d != "/" && strings.Count(d, "/") >= 2 && d != h && len(out) < 5; d = filepath.Dir(d) {
		out = append(out, d+"/***")
	}
	return slices.Compact(out)
}

// LearnRoot collapses a path to the folder a person would approve:
// ~/.pi/agent/x -> ~/.pi, ~/.local/share/pnpm/store/... -> ~/.local/share/pnpm,
// ~/.config/gh/x -> ~/.config/gh, elsewhere -> the file's directory.
func LearnRoot(p string) string {
	h := system.Home()
	if !system.Under(p, h) || p == h {
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

// HostOf strips protocol and port from a host card target.
func HostOf(target string) string {
	if _, rest, ok := strings.Cut(target, "://"); ok {
		target = rest
	}
	if i := strings.LastIndex(target, ":"); i >= 0 && !strings.HasSuffix(target, "]") {
		target = target[:i]
	}
	return target
}

func Ignored(r []Rules, kind, target string) bool {
	for _, rules := range r {
		for _, p := range rules.Ignore {
			if kind == "hosts" {
				host := HostOf(target)
				if h, err := ParseHostRule(p); err == nil && (h.Host == host || h.Host == "*" || (strings.HasPrefix(h.Host, "*.") && strings.HasSuffix(host, h.Host[1:]))) {
					return true
				}
			} else if p == target || (strings.HasPrefix(p, "/") && MatchPath(p, target)) {
				return true
			}
		}
	}
	return false
}
