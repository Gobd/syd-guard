package guest

import (
	"net/netip"
	"testing"
)

func TestAddrClass(t *testing.T) {
	for ip, want := range map[string]string{
		"127.0.0.1": "blocked", "::1": "blocked", "169.254.169.254": "blocked", "0.0.0.0": "blocked",
		"10.1.2.3": "private", "192.168.5.2": "private", "100.64.1.1": "private", "fd00::1": "private",
		"93.184.216.34": "public", "2606:4700::1": "public", "::ffff:127.0.0.1": "blocked",
	} {
		if got := addrClass(netip.MustParseAddr(ip)); got != want {
			t.Errorf("addrClass(%s) = %s, want %s", ip, got, want)
		}
	}
}
