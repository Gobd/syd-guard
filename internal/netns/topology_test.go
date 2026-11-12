package netns

import (
	"net/netip"
	"strings"
	"testing"
)

func TestFirewallBeforeLinkActivationAndNoGlobalEdits(t *testing.T) {
	topology, err := New()
	if err != nil {
		t.Fatal(err)
	}
	commands, err := topology.Prepare(53001, 53002)
	if err != nil {
		t.Fatal(err)
	}
	firewall := false
	for _, command := range commands {
		if command.Program == "nft" {
			firewall = true
			if !strings.Contains(command.Input, "iifname \""+topology.HostLink+"\" drop") {
				t.Fatal("missing default drop")
			}
			if strings.Count(command.Input, "ct status dnat") != 2 {
				t.Fatal("data-plane listeners must only accept redirected traffic")
			}
			if !strings.HasPrefix(command.Input, "create table inet "+topology.Table+"\n") {
				t.Fatal("nft table creation must fail on collisions")
			}
		}
		args := strings.Join(command.Args, " ")
		if strings.Contains(args, " up") && !firewall {
			t.Fatal("link activated before deny firewall")
		}
		if strings.Contains(args, "flush") || strings.Contains(args, "ip_forward") || strings.Contains(args, "tun") {
			t.Fatal("global edit or TUN dependency")
		}
	}
	if _, err := topology.UserExec(0, 1000, []string{"anything"}); err == nil {
		t.Fatal("root workload allowed")
	}
	topology.Namespace = "other-existing-netns"
	if _, err := topology.Cleanup(); err == nil {
		t.Fatal("cleanup could delete another namespace")
	}
}

func TestTopologyRejectsInvalidTransitAddresses(t *testing.T) {
	original, err := New()
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Topology){
		func(t *Topology) { t.Agent = t.Host },
		func(t *Topology) { t.Agent = t.Prefix.Addr() },
		func(t *Topology) { t.Host = netip.MustParseAddr("192.0.2.1") },
		func(t *Topology) { t.Prefix = netip.PrefixFrom(t.Host, 30) },
	} {
		value := original
		change(&value)
		if err := value.Validate(); err == nil {
			t.Fatalf("accepted invalid transit topology: %+v", value)
		}
	}
}
