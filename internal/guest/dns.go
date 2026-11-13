package guest

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/Gobd/syd-guard/internal/policy"
	"github.com/Gobd/syd-guard/internal/system"
)

// Each session gets its own DNS server on a private loopback address
// (127.53.x.y:53); Syd bind-mounts a resolv.conf pointing at it. Names are
// only resolved if a host rule allows them, and the returned IPs are then
// allowed in Syd for the rule's ports. That gives tools that ignore the HTTP
// proxy (psql, redis-cli, ssh-less git, UDP...) host-NAME rules, and closes
// DNS as a way to leak data through unapproved names.

const dnsWait = 4 * time.Second // resolvers retry; a card can be approved meanwhile

type dnsServer struct {
	d      *Daemon
	s      *Session
	udp    *net.UDPConn
	tcp    net.Listener
	mu     sync.Mutex
	Names  map[string]string          `json:"names"`  // ip -> name
	Grants map[string]map[string]bool `json:"grants"` // host rule -> "ip!ports"
}

func (d *Daemon) startDNS(s *Session) error {
	addr := s.DNSAddr
	var udp *net.UDPConn
	var tcp net.Listener
	var err error
	for range 20 {
		if addr == "" {
			addr = fmt.Sprintf("127.53.%d.%d:53", rand.IntN(254)+1, rand.IntN(254)+1)
		}
		ua, _ := net.ResolveUDPAddr("udp", addr)
		if udp, err = net.ListenUDP("udp", ua); err == nil {
			if tcp, err = net.Listen("tcp", addr); err == nil {
				break
			}
			_ = udp.Close()
		}
		if s.DNSAddr != "" {
			return err // adopting: must keep the same address
		}
		addr = ""
	}
	if err != nil {
		return fmt.Errorf("dns listen: %w", err)
	}
	srv := &dnsServer{d: d, s: s, udp: udp, tcp: tcp, Names: map[string]string{}, Grants: map[string]map[string]bool{}}
	if data, err := os.ReadFile(srv.statePath()); err == nil {
		_ = json.Unmarshal(data, srv)
	}
	s.DNSAddr, s.dns = addr, srv
	go srv.serveUDP()
	go srv.serveTCP()
	return nil
}

func (x *dnsServer) statePath() string { return filepath.Join(sessionsDir(), x.s.ID+".dns.json") }

func (x *dnsServer) save() {
	x.mu.Lock()
	data, _ := json.Marshal(x)
	x.mu.Unlock()
	_ = os.WriteFile(x.statePath(), data, 0o600)
}

func (x *dnsServer) close() { _ = x.udp.Close(); _ = x.tcp.Close() }

func (x *dnsServer) nameOf(ip string) string {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.Names[ip]
}

func (x *dnsServer) serveUDP() {
	buf := make([]byte, 4096)
	for {
		n, from, err := x.udp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		q := append([]byte(nil), buf[:n]...)
		go func() {
			if resp := x.handle(q, "udp"); resp != nil {
				_, _ = x.udp.WriteToUDP(resp, from)
			}
		}()
	}
}

func (x *dnsServer) serveTCP() {
	for {
		c, err := x.tcp.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(30 * time.Second))
			for {
				q, err := readTCPMsg(c)
				if err != nil {
					return
				}
				resp := x.handle(q, "tcp")
				if resp == nil || writeTCPMsg(c, resp) != nil {
					return
				}
			}
		}()
	}
}

func readTCPMsg(r io.Reader) ([]byte, error) {
	var n uint16
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

func writeTCPMsg(w io.Writer, b []byte) error {
	if err := binary.Write(w, binary.BigEndian, uint16(len(b))); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

// refuse builds a REFUSED reply for query q.
func refuse(q []byte, rcode dnsmessage.RCode) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil {
		return nil
	}
	qs, _ := p.AllQuestions()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RCode: rcode, RecursionDesired: h.RecursionDesired, RecursionAvailable: true})
	_ = b.StartQuestions()
	for _, qq := range qs {
		_ = b.Question(qq)
	}
	out, _ := b.Finish()
	return out
}

func (x *dnsServer) handle(q []byte, proto string) []byte {
	var p dnsmessage.Parser
	if _, err := p.Start(q); err != nil {
		return nil
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) != 1 {
		return refuse(q, dnsmessage.RCodeFormatError)
	}
	name := strings.ToLower(strings.TrimSuffix(qs[0].Name.String(), "."))
	if _, err := policy.ParseHostRule(name); err != nil || system.SafeText(name) != nil {
		return refuse(q, dnsmessage.RCodeRefused)
	}
	rules := x.rules()
	if policy.Ignored(rules, "hosts", "dns://"+name) {
		return refuse(q, dnsmessage.RCodeRefused)
	}
	matching := matchingRules(rules, name)
	if len(matching) == 0 {
		if !x.ask(name) {
			return refuse(q, dnsmessage.RCodeRefused)
		}
		matching = matchingRules(x.rules(), name)
	}
	resp, err := forward(q, proto)
	if err != nil {
		return refuse(q, dnsmessage.RCodeServerFailure)
	}
	x.grant(name, resp, matching)
	return resp
}

func (x *dnsServer) rules() []policy.Rules {
	return []policy.Rules{x.d.store.Get(system.GlobalRulesPath()), x.d.store.Get(x.s.RulesFile)}
}

func matchingRules(rules []policy.Rules, name string) []policy.HostRule {
	var out []policy.HostRule
	for _, r := range rules {
		for _, p := range r.Hosts {
			if h, err := policy.ParseHostRule(p); err == nil && h.MatchName(name) {
				out = append(out, h)
			}
		}
	}
	return out
}

// ask shows a card for an unknown name and waits briefly. Learn mode allows
// everything and records it.
func (x *dnsServer) ask(name string) bool {
	x.d.mu.Lock()
	if _, live := x.d.sessions[x.s.ID]; !live {
		x.d.mu.Unlock()
		return false
	}
	c := x.d.addCardLocked(x.s, "hosts", "dns://"+name, "", x.s.Learn, false,
		"name lookup — approve to let tools that bypass the proxy connect to it (add :port to limit)")
	if x.s.Learn || c == nil {
		x.d.mu.Unlock()
		x.d.events.Notify()
		return x.s.Learn
	}
	return x.d.waitCard(context.Background(), c, dnsWait)
}

var upstreamOnce = sync.OnceValue(func() string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if f := strings.Fields(line); len(f) == 2 && f[0] == "nameserver" {
				if a, err := netip.ParseAddr(f[1]); err == nil {
					return net.JoinHostPort(a.String(), "53")
				}
			}
		}
	}
	return "127.0.0.53:53"
})

func forward(q []byte, proto string) ([]byte, error) {
	c, err := net.DialTimeout(proto, upstreamOnce(), 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if proto == "tcp" {
		if err := writeTCPMsg(c, q); err != nil {
			return nil, err
		}
		return readTCPMsg(c)
	}
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	return buf[:n], err
}

// grant allows the answer's IPs on the matching rules' ports, live, before
// the answer is returned (so the following connect works).
func (x *dnsServer) grant(name string, resp []byte, rules []policy.HostRule) {
	var p dnsmessage.Parser
	if _, err := p.Start(resp); err != nil {
		return
	}
	_ = p.SkipAllQuestions()
	answers, _ := p.AllAnswers()
	var ips []netip.Addr
	for _, a := range answers {
		switch r := a.Body.(type) {
		case *dnsmessage.AResource:
			ips = append(ips, netip.AddrFrom4(r.A))
		case *dnsmessage.AAAAResource:
			ips = append(ips, netip.AddrFrom16(r.AAAA))
		}
	}
	var cmds []string
	x.mu.Lock()
	for _, ip := range ips {
		class := addrClass(ip)
		x.Names[ip.Unmap().String()] = name
		for _, h := range rules {
			if class == "blocked" || (class == "private" && !h.Exact()) {
				continue
			}
			key := h.String()
			if x.Grants[key] == nil {
				x.Grants[key] = map[string]bool{}
			}
			target := ip.Unmap().String() + "!" + h.PortRange()
			if !x.Grants[key][target] {
				x.Grants[key][target] = true
				cmds = append(cmds, "allow/net/connect+"+target)
			}
		}
	}
	x.mu.Unlock()
	if len(cmds) > 0 {
		if res := x.d.pushOne(x.s, cmds); !res.Applied {
			log.Printf("session %s dns grant %s: %s", x.s.ID, name, res.Error)
		}
		x.save()
	}
}

// revokeRemoved returns the Syd commands that take back IPs granted by host
// rules that were removed (and aren't still present in another rules file).
func (x *dnsServer) revokeRemoved(before, after policy.Rules) []string {
	still := map[string]bool{}
	for _, r := range x.rules() {
		for _, p := range r.Hosts {
			still[p] = true
		}
	}
	for _, p := range after.Hosts {
		still[p] = true
	}
	var cmds []string
	x.mu.Lock()
	for _, p := range before.Hosts {
		h, err := policy.ParseHostRule(p)
		if err != nil || still[p] {
			continue
		}
		for target := range x.Grants[h.String()] {
			cmds = append(cmds, "allow/net/connect-"+target)
		}
		delete(x.Grants, h.String())
	}
	x.mu.Unlock()
	if len(cmds) > 0 {
		go x.save()
	}
	return cmds
}

// Overlays ------------------------------------------------------------------

// overlayDirs picks build/dependency folders to keep on the VM disk instead of
// the (host-mounted) project. Known names follow their ecosystem's markers:
// node_modules next to every package.json, .venv for Python, target for Rust;
// other names apply at the project root if that folder exists. Missing known
// folders are created empty.
func overlayDirs(project string, names []string) []string {
	var out []string
	add := func(rel string) {
		if strings.Contains(rel, ":") || len(out) >= 64 || slices.Contains(out, rel) {
			return
		}
		_ = os.MkdirAll(filepath.Join(project, rel), 0o755)
		out = append(out, rel)
	}
	exists := func(rel string) bool { _, err := os.Stat(filepath.Join(project, rel)); return err == nil }
	for _, n := range names {
		switch n {
		case ".venv":
			if exists("pyproject.toml") || exists("requirements.txt") || exists(".venv") {
				add(".venv")
			}
		case "target":
			if exists("Cargo.toml") {
				add("target")
			}
		case "node_modules":
			_ = filepath.WalkDir(project, func(p string, e os.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				rel, _ := filepath.Rel(project, p)
				if e.IsDir() {
					if base := e.Name(); rel != "." && (base == "node_modules" || base == ".git" || strings.Count(rel, "/") >= 3) {
						return filepath.SkipDir
					}
					return nil
				}
				if e.Name() == "package.json" {
					add(filepath.Join(filepath.Dir(rel), "node_modules"))
				}
				return nil
			})
		default:
			if exists(n) {
				add(n)
			}
		}
	}
	return out
}

func overlaySource(project, rel string) string {
	dir := filepath.Join(system.Home(), ".cache", "sydguard", "overlay", system.HashBytes([]byte(project))[:16], rel)
	_ = os.MkdirAll(dir, 0o755)
	return dir
}
