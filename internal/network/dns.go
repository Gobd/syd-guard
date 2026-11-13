package network

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// DNS generates synthetic A answers; it never grants network permissions.
// AAAA returns no data for the initial IPv4-only topology. Other record types
// are refused explicitly rather than forwarding arbitrary DNS payloads.
type DNS struct {
	Address   string
	synthetic *Synthetic
	agent     netip.Addr
	udp       *net.UDPConn
	tcp       net.Listener
}

func StartDNS(synthetic *Synthetic, agent netip.Addr) (*DNS, error) {
	if !agent.Is4() {
		return nil, fmt.Errorf("session IPv4 source required")
	}
	//nolint:gosec // veth data plane only; not an operator API; ingress is isolated by session nftables
	tcp, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: tcp.Addr().(*net.TCPAddr).Port})
	if err != nil {
		_ = tcp.Close()
		return nil, err
	}
	dns, err := StartDNSPrebound(synthetic, agent, tcp.(*net.TCPListener), udp)
	if err != nil {
		_ = tcp.Close()
		_ = udp.Close()
		return nil, err
	}
	return dns, nil
}

// StartDNSPrebound takes ownership of both sockets only on success. The caller
// must independently authenticate the descriptors and their network namespace.
func StartDNSPrebound(synthetic *Synthetic, agent netip.Addr, tcp *net.TCPListener, udp *net.UDPConn) (*DNS, error) {
	if synthetic == nil || !agent.Is4() || tcp == nil || udp == nil {
		return nil, fmt.Errorf("invalid prebound DNS arguments")
	}
	tcpAddr, ok := tcp.Addr().(*net.TCPAddr)
	if !ok || tcpAddr == nil {
		return nil, fmt.Errorf("invalid prebound DNS TCP address")
	}
	udpAddr, ok := udp.LocalAddr().(*net.UDPAddr)
	if !ok || udpAddr == nil || udp.RemoteAddr() != nil {
		return nil, fmt.Errorf("invalid prebound DNS UDP address")
	}
	if !socketOpen(tcp) || !socketOpen(udp) {
		return nil, fmt.Errorf("prebound DNS socket is closed")
	}
	t, u := tcpAddr.AddrPort(), udpAddr.AddrPort()
	if !t.Addr().Is4() || !u.Addr().Is4() || t.Port() == 0 || t != u {
		return nil, fmt.Errorf("prebound DNS sockets must share an IPv4 address and port")
	}
	dns := &DNS{Address: tcp.Addr().String(), synthetic: synthetic, agent: agent, udp: udp, tcp: tcp}
	go dns.serveUDP()
	go dns.serveTCP()
	return dns, nil
}
func (d *DNS) Close() { _ = d.udp.Close(); _ = d.tcp.Close() }
func (d *DNS) answer(packet []byte) ([]byte, error) {
	if len(packet) > 4096 {
		return nil, fmt.Errorf("DNS packet exceeds bound")
	}
	var request dnsmessage.Message
	if err := request.Unpack(packet); err != nil {
		return nil, err
	}
	response := dnsmessage.Message{Header: dnsmessage.Header{ID: request.ID, Response: true, RecursionDesired: request.RecursionDesired}, Questions: request.Questions}
	if request.Response || len(request.Questions) != 1 || request.OpCode != 0 {
		response.RCode = dnsmessage.RCodeFormatError
		return response.Pack()
	}
	question := request.Questions[0]
	if question.Class != dnsmessage.ClassINET {
		response.RCode = dnsmessage.RCodeRefused
		return response.Pack()
	}
	if question.Type == dnsmessage.TypeAAAA {
		return response.Pack()
	}
	if question.Type != dnsmessage.TypeA {
		response.RCode = dnsmessage.RCodeRefused
		return response.Pack()
	}
	address, err := d.synthetic.Address(question.Name.String())
	if err != nil {
		response.RCode = dnsmessage.RCodeRefused
		return response.Pack()
	}
	response.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: address.As4()}}}
	return response.Pack()
}

func (d *DNS) serveUDP() {
	buffer := make([]byte, 4096)
	for {
		n, peer, err := d.udp.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		if peer.AddrPort().Addr().Unmap() != d.agent {
			continue
		}
		answer, err := d.answer(buffer[:n])
		if err == nil {
			_, _ = d.udp.WriteToUDP(answer, peer)
		}
	}
}

func (d *DNS) serveTCP() {
	slots := make(chan struct{}, 16)
	for {
		conn, err := d.tcp.Accept()
		if err != nil {
			return
		}
		peer, ok := netip.AddrFromSlice(conn.RemoteAddr().(*net.TCPAddr).IP)
		if !ok || peer.Unmap() != d.agent {
			_ = conn.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
			go func() {
				defer func() { _ = conn.Close(); <-slots }()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				var length [2]byte
				if _, err := io.ReadFull(conn, length[:]); err != nil {
					return
				}
				size := binary.BigEndian.Uint16(length[:])
				if size > 4096 {
					return
				}
				packet := make([]byte, size)
				if _, err := io.ReadFull(conn, packet); err != nil {
					return
				}
				answer, err := d.answer(packet)
				if err != nil {
					return
				}
				if len(answer) > 4096 {
					return
				}
				binary.BigEndian.PutUint16(length[:], uint16(len(answer))) //nolint:gosec // response is bounded to 4096 bytes immediately above
				_, _ = conn.Write(append(length[:], answer...))
			}()
		default:
			_ = conn.Close()
		}
	}
}
