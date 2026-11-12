package syd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

var syntheticRange = netip.MustParsePrefix("198.18.0.0/15")

// ParseSyntheticConnectDenial accepts only a trusted Syd logging-descriptor
// record for an IPv4 TCP connect to the synthetic pool. DNS provenance must
// still be checked against the originating session's mapping by the caller.
func ParseSyntheticConnectDenial(data []byte) (netip.AddrPort, bool) {
	var event struct {
		Context    string `json:"ctx"`
		Capability string `json:"cap"`
		Action     string `json:"act"`
		Syscall    string `json:"sys"`
		Address    string `json:"addr"`
		IPVersion  int    `json:"ipv"`
		Protocol   string `json:"proto"`
	}
	if json.Unmarshal(data, &event) != nil || event.Context != "access" || event.Capability != "net/connect" || event.Action != "deny" || event.Syscall != "connect" || event.IPVersion != 4 || event.Protocol != "tcp" {
		return netip.AddrPort{}, false
	}
	parts := strings.Split(event.Address, "!")
	if len(parts) != 3 || parts[0] != "tcp" {
		return netip.AddrPort{}, false
	}
	address, err := netip.ParseAddr(parts[1])
	if err != nil || !address.Is4() || !syntheticRange.Contains(address) {
		return netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(parts[2], 10, 16)
	if err != nil || port == 0 || strconv.FormatUint(port, 10) != parts[2] {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(address, uint16(port)), true
}

// GrantSyntheticTCP installs one exact session-authorized endpoint. It does not
// authorize a hostname, port range, raw IP, other transport or Landlock ceiling.
func (client IPC) GrantSyntheticTCP(ctx context.Context, endpoint netip.AddrPort) error {
	if !endpoint.Addr().Is4() || !syntheticRange.Contains(endpoint.Addr()) || endpoint.Port() == 0 {
		return fmt.Errorf("exact synthetic IPv4 TCP endpoint required")
	}
	var ack struct {
		Err     int    `json:"err"`
		Message string `json:"msg"`
	}
	if err := client.exchange(ctx, fmt.Sprintf("allow/net/connect+tcp!%s!%d", endpoint.Addr(), endpoint.Port()), &ack); err != nil {
		return err
	}
	if ack.Err != 0 || ack.Message != "ACK" {
		return fmt.Errorf("syd rejected synthetic TCP grant: errno=%d message=%s", ack.Err, ack.Message)
	}
	return nil
}

// TransparentRules permits only the session transit resolver. Synthetic TCP
// remains denied until the controller installs an exact IPC grant.
func TransparentRules(address string) (string, error) {
	ip, err := netip.ParseAddr(address)
	if err != nil || !ip.Is4() || !netip.MustParsePrefix("10.232.0.0/16").Contains(ip) || ip.String() != address {
		return "", fmt.Errorf("invalid transit resolver")
	}
	return fmt.Sprintf("allow/net/connect+tcp!%s!53\nallow/net/connect+udp!%s!53\nallow/lock/connect+1-65535\n", address, address), nil
}

// GatewayRules admits only this session's trusted loop's trusted loopback proxy. Direct DNS,
// remote sockets, other sessions and operator control sockets remain denied.
func GatewayRules(endpoint string) (string, error) {
	host, text, err := net.SplitHostPort(endpoint)
	if err != nil || host != "127.0.0.1" {
		return "", fmt.Errorf("gateway must be an exact IPv4 loopback endpoint")
	}
	port, err := strconv.ParseUint(text, 10, 16)
	if err != nil || port == 0 {
		return "", fmt.Errorf("invalid gateway port")
	}
	return fmt.Sprintf("allow/net/connect+tcp!127.0.0.1!%d\nallow/lock/connect+%d\n", port, port), nil
}
