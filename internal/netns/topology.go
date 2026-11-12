// Package netns plans session-owned Linux veth/nftables resources. No TUN,
// global forwarding changes, default-route edits or arbitrary root argv.
package netns

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type (
	Command struct {
		Program string
		Args    []string
		Input   string
	}
	Topology struct {
		ID, Namespace, HostLink, PeerLink, Table string
		Host, Agent                              netip.Addr
		Prefix                                   netip.Prefix
	}
)

func New() (Topology, error) {
	var bytes [6]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return Topology{}, err
	}
	id := hex.EncodeToString(bytes[:3])
	third := bytes[3]
	base := bytes[4] % 64 * 4
	host := netip.AddrFrom4([4]byte{10, 232, third, base + 1})
	agent := netip.AddrFrom4([4]byte{10, 232, third, base + 2})
	return Topology{ID: id, Namespace: "sg-" + id, HostLink: "sgh-" + id, PeerLink: "sga-" + id, Table: "sg_" + id, Host: host, Agent: agent, Prefix: netip.PrefixFrom(host, 30).Masked()}, nil
}

func (t Topology) Validate() error {
	if len(t.ID) != 6 || strings.ContainsAny(t.ID, "\r\n \t/;\"'") {
		return fmt.Errorf("invalid generated topology ID")
	}
	if _, err := hex.DecodeString(t.ID); err != nil {
		return err
	}
	if t.ID != strings.ToLower(t.ID) {
		return fmt.Errorf("topology ID must be lowercase")
	}
	if t.Namespace != "sg-"+t.ID || t.HostLink != "sgh-"+t.ID || t.PeerLink != "sga-"+t.ID || t.Table != "sg_"+t.ID {
		return fmt.Errorf("topology resource names are not derived from its ID")
	}
	if !t.Host.Is4() || !t.Agent.Is4() || !t.Prefix.IsValid() || t.Prefix.Bits() != 30 || t.Prefix != t.Prefix.Masked() || !netip.MustParsePrefix("10.232.0.0/16").Contains(t.Host) || t.Host != t.Prefix.Addr().Next() || t.Agent != t.Host.Next() {
		return fmt.Errorf("invalid session transit addresses")
	}
	return nil
}

// Prepare only creates named session resources. nft redirects synthetic TCP
// traffic and controlled DNS to protected host-side services. Everything else
// entering the host or forwarding from this veth is dropped independently of Syd.
func (t Topology) Prepare(dnsPort, tcpPort uint16) ([]Command, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	if dnsPort == 0 || tcpPort == 0 || dnsPort == tcpPort {
		return nil, fmt.Errorf("two distinct protected data-plane ports are required")
	}
	commands := []Command{
		{Program: "ip", Args: []string{"netns", "add", t.Namespace}},
		{Program: "ip", Args: []string{"link", "add", t.HostLink, "type", "veth", "peer", "name", t.PeerLink}},
		{Program: "ip", Args: []string{"link", "set", t.PeerLink, "netns", t.Namespace}},
		{Program: "ip", Args: []string{"addr", "add", t.Host.String() + "/30", "dev", t.HostLink}},

		{Program: "ip", Args: []string{"-n", t.Namespace, "addr", "add", t.Agent.String() + "/30", "dev", t.PeerLink}},
	}
	rules := fmt.Sprintf(`create table inet %s
table inet %s {
 chain sg_pre {
  type nat hook prerouting priority dstnat; policy accept;
  iifname "%s" ip daddr %s udp dport 53 redirect to :%d
  iifname "%s" ip daddr %s tcp dport 53 redirect to :%d
  iifname "%s" ip daddr 198.18.0.0/15 meta l4proto tcp redirect to :%d
 }
 chain sg_input {
  type filter hook input priority -10; policy accept;
  iifname "%s" ip saddr != %s drop
  iifname "%s" ct status dnat meta l4proto tcp tcp dport {%d,%d} accept
  iifname "%s" ct status dnat meta l4proto udp udp dport %d accept
  iifname "%s" drop
 }
 chain sg_forward {
  type filter hook forward priority -10; policy accept;
  iifname "%s" drop
  oifname "%s" drop
 }
}
`, t.Table, t.Table, t.HostLink, t.Host, dnsPort, t.HostLink, t.Host, dnsPort, t.HostLink, tcpPort, t.HostLink, t.Agent, t.HostLink, dnsPort, tcpPort, t.HostLink, dnsPort, t.HostLink, t.HostLink, t.HostLink)
	commands = append(commands, Command{Program: "nft", Args: []string{"-f", "-"}, Input: rules},
		Command{Program: "ip", Args: []string{"link", "set", t.HostLink, "up"}},
		Command{Program: "ip", Args: []string{"-n", t.Namespace, "link", "set", "lo", "up"}},
		Command{Program: "ip", Args: []string{"-n", t.Namespace, "link", "set", t.PeerLink, "up"}},
		Command{Program: "ip", Args: []string{"-n", t.Namespace, "route", "add", "default", "via", t.Host.String(), "dev", t.PeerLink}})
	return commands, nil
}

func (t Topology) Cleanup() ([]Command, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return []Command{{Program: "nft", Args: []string{"delete", "table", "inet", t.Table}}, {Program: "ip", Args: []string{"link", "del", t.HostLink}}, {Program: "ip", Args: []string{"netns", "del", t.Namespace}}}, nil
}

// UserExec drops root before the trusted wrapper or workload is executed. This
// is a plan only; production must hold resources disabled until firewall setup
// completes and validate the approved executable separately.
func (t Topology) UserExec(uid, gid int, argv []string) (Command, error) {
	if err := t.Validate(); err != nil {
		return Command{}, err
	}
	if uid <= 0 || gid <= 0 || len(argv) == 0 {
		return Command{}, fmt.Errorf("non-root numeric user/group and executable required")
	}
	args := []string{"netns", "exec", t.Namespace, "setpriv", "--reuid", strconv.Itoa(uid), "--regid", strconv.Itoa(gid), "--clear-groups", "--no-new-privs", "--bounding-set=-all", "--"}
	return Command{Program: "ip", Args: append(args, argv...)}, nil
}
