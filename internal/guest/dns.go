package guest

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/Gobd/syd-guard/internal/policy"
	"github.com/Gobd/syd-guard/internal/system"
)

const (
	maxDNSNames = 8192
)

var (
	synthetic4 = netip.MustParsePrefix("198.18.0.0/15")
	synthetic6 = netip.MustParsePrefix("fd53::/96")
)

// Synthetic answers preserve name identity even when unrelated domains share
// a CDN IP. Mappings never expire/reassign during a session (clients cache DNS).
// Real resolution happens in the daemon only after connection approval.
type dnsServer struct {
	d     *Daemon
	s     *Session
	mu    sync.Mutex
	Names []string `json:"names"`
}

func (d *Daemon) startDNS(s *Session) error {
	x := &dnsServer{d: d, s: s}
	if data, err := os.ReadFile(x.statePath()); err == nil {
		if err := json.Unmarshal(data, x); err != nil {
			return err
		}
		if len(x.Names) > maxDNSNames {
			return errors.New("too many saved DNS names")
		}
	}
	s.DNSAddr, s.dns = networkGateway+":53", x
	return nil
}

func (x *dnsServer) statePath() string { return filepath.Join(sessionsDir(), x.s.ID+".dns.json") }
func fakeIP(index int, ipv6 bool) netip.Addr {
	if ipv6 {
		a := synthetic6.Addr().As16()
		binary.BigEndian.PutUint32(a[12:], uint32(index+1))
		return netip.AddrFrom16(a)
	}
	a := synthetic4.Addr().As4()
	binary.BigEndian.PutUint16(a[2:], uint16(index+1))
	return netip.AddrFrom4(a)
}

func (x *dnsServer) nameOf(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	a = a.Unmap()
	index := -1
	if synthetic4.Contains(a) {
		b := a.As4()
		index = int(binary.BigEndian.Uint16(b[2:])) - 1
	}
	if synthetic6.Contains(a) {
		b := a.As16()
		index = int(binary.BigEndian.Uint32(b[12:])) - 1
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if index >= 0 && index < len(x.Names) {
		return x.Names[index]
	}
	return ""
}

func (x *dnsServer) address(name string, ipv6 bool) (netip.Addr, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	for i, n := range x.Names {
		if n == name {
			return fakeIP(i, ipv6), nil
		}
	}
	if len(x.Names) >= maxDNSNames {
		return netip.Addr{}, errors.New("session DNS map full")
	}
	x.Names = append(x.Names, name)
	data, err := json.Marshal(x)
	if err == nil {
		err = os.WriteFile(x.statePath()+".tmp", data, 0o600)
	}
	if err == nil {
		err = os.Rename(x.statePath()+".tmp", x.statePath())
	}
	if err != nil {
		x.Names = x.Names[:len(x.Names)-1]
		return netip.Addr{}, err
	}
	return fakeIP(len(x.Names)-1, ipv6), nil
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
	if len(b) > 65535 {
		return errors.New("DNS message too large")
	}
	if err := binary.Write(w, binary.BigEndian, uint16(len(b))); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

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
	h, err := p.Start(q)
	if err != nil {
		return nil
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) != 1 || h.Response || h.OpCode != 0 || qs[0].Class != dnsmessage.ClassINET {
		return refuse(q, dnsmessage.RCodeFormatError)
	}
	name := strings.ToLower(strings.TrimSuffix(qs[0].Name.String(), "."))
	if _, err := policy.ParseHostRule(name); err != nil || strings.Contains(name, "*") {
		return refuse(q, dnsmessage.RCodeRefused)
	}
	if policy.Ignored(x.rules(), "hosts", "dns://"+name) {
		return refuse(q, dnsmessage.RCodeRefused)
	}
	// A/AAAA answers are entirely local synthetic identities, not upstream
	// lookups. Approval happens on the connection with its actual protocol
	// and port, never as a broad tcp:// grant just to obtain an address.
	// HTTPS/SVCB records could disclose real addresses or advertise ECH, which
	// hides SNI. Return NODATA; clients fall back to ordinary A/AAAA + TLS.
	if qs[0].Type != dnsmessage.TypeA && qs[0].Type != dnsmessage.TypeAAAA {
		if qs[0].Type != dnsmessage.TypeTXT && qs[0].Type != dnsmessage.TypeMX && qs[0].Type != dnsmessage.TypeSRV {
			return refuse(q, dnsmessage.RCodeSuccess)
		}
		if len(matchingRules(x.rules(), name)) == 0 {
			return refuse(q, dnsmessage.RCodeRefused)
		}
		resp, err := forward(q, proto)
		if err != nil {
			return refuse(q, dnsmessage.RCodeServerFailure)
		}
		return resp
	}
	ip, err := x.address(name, qs[0].Type == dnsmessage.TypeAAAA)
	if err != nil {
		return refuse(q, dnsmessage.RCodeServerFailure)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true})
	b.EnableCompression()
	_ = b.StartQuestions()
	_ = b.Question(qs[0])
	_ = b.StartAnswers()
	rh := dnsmessage.ResourceHeader{Name: qs[0].Name, Type: qs[0].Type, Class: dnsmessage.ClassINET, TTL: 60}
	if ip.Is4() {
		_ = b.AResource(rh, dnsmessage.AResource{A: ip.As4()})
	} else {
		_ = b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: ip.As16()})
	}
	out, _ := b.Finish()
	return out
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

// Read the current host resolver each time: VPN/Lima/resolved changes should
// not permanently pin sessions to a dead server. No public fallback (DNS leak).
func upstreamServers() []string {
	data, _ := os.ReadFile("/etc/resolv.conf")
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			if a, err := netip.ParseAddr(f[1]); err == nil {
				out = append(out, net.JoinHostPort(a.String(), "53"))
			}
		}
	}
	return out
}

func forward(q []byte, proto string) ([]byte, error) {
	last := errors.New("no host DNS resolvers configured")
	for _, server := range upstreamServers() {
		resp, err := exchangeDNS(q, proto, server)
		if err == nil {
			return resp, nil
		}
		last = err
	}
	return nil, last
}

func exchangeDNS(q []byte, proto, server string) ([]byte, error) {
	c, err := net.DialTimeout(proto, server, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	var resp []byte
	if proto == "tcp" {
		if err = writeTCPMsg(c, q); err == nil {
			resp, err = readTCPMsg(c)
		}
	} else {
		if _, err = c.Write(q); err == nil {
			resp = make([]byte, 65535)
			var size int
			size, err = c.Read(resp)
			resp = resp[:size]
		}
	}
	if err != nil {
		return nil, err
	}
	var query, reply dnsmessage.Message
	if query.Unpack(q) != nil || reply.Unpack(resp) != nil || !reply.Response || reply.ID != query.ID || len(query.Questions) != 1 || len(reply.Questions) != 1 || query.Questions[0] != reply.Questions[0] {
		return nil, errors.New("invalid upstream DNS response")
	}
	if reply.Truncated && proto == "udp" {
		return exchangeDNS(q, "tcp", server)
	}
	if reply.RCode == dnsmessage.RCodeServerFailure {
		return nil, errors.New("upstream DNS SERVFAIL")
	}
	return resp, nil
}
