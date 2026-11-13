//go:build linux

package guest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"github.com/xjasonlyu/tun2socks/v2/core/device/fdbased"
	"golang.org/x/sys/unix"
)

func tunSocket(id string) string { return filepath.Join(sessionsDir(), id+".tun.sock") }

func (d *Daemon) startNetwork(s *Session) error {
	n := newNetwork(d, s)
	_ = os.Remove(tunSocket(s.ID))
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: tunSocket(s.ID), Net: "unix"})
	if err != nil {
		n.cancel()
		return err
	}
	_ = os.Chmod(tunSocket(s.ID), 0o600)
	n.stop = func() { _ = ln.Close() }
	s.network = n
	go func() {
		c, err := ln.AcceptUnix()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(15 * time.Second))
		fds, err := receiveFDs(c)
		if err != nil {
			return
		}
		defer func() {
			for _, fd := range fds {
				_ = unix.Close(fd)
			}
		}()
		if len(fds) != 1+2*len(s.LocalPorts) {
			return
		}
		// Dup ownership into the endpoint; the received descriptors are always
		// closed, including all error paths. A TUN disappearing removes routes.
		fd, err := unix.Dup(fds[0])
		if err != nil {
			return
		}
		dev, err := fdbased.Open(strconv.Itoa(fd), 1500, 0)
		if err != nil {
			_ = unix.Close(fd)
			return
		}
		st, err := core.CreateStack(&core.Config{LinkEndpoint: dev, TransportHandler: n})
		if err != nil {
			dev.Close()
			return
		}
		var listeners []net.Listener
		var packets []net.PacketConn
		cleanup := func() {
			for _, l := range listeners {
				_ = l.Close()
			}
			for _, p := range packets {
				_ = p.Close()
			}
			st.Close()
			dev.Close()
			st.Wait()
		}
		for i, port := range s.LocalPorts {
			f := os.NewFile(uintptr(fds[1+2*i]), "local-tcp")
			l, err := net.FileListener(f)
			_ = f.Close()
			fds[1+2*i] = -1
			if err != nil {
				cleanup()
				return
			}
			listeners = append(listeners, l)
			f = os.NewFile(uintptr(fds[2+2*i]), "local-udp")
			p, err := net.FilePacketConn(f)
			_ = f.Close()
			fds[2+2*i] = -1
			if err != nil {
				cleanup()
				return
			}
			packets = append(packets, p)
			go n.localTCP(l, port)
			go n.localUDP(p, port)
		}
		n.mu.Lock()
		if n.ctx.Err() != nil {
			n.mu.Unlock()
			cleanup()
			return
		}
		n.stop = func() { _ = ln.Close(); cleanup() }
		n.mu.Unlock()
		_, _ = c.Write([]byte("ok"))
	}()
	return nil
}

func receiveFDs(c *net.UnixConn) ([]int, error) {
	b, oob := make([]byte, 1), make([]byte, unix.CmsgSpace(129*4))
	_, size, flags, _, err := c.ReadMsgUnix(b, oob)
	if err != nil {
		return nil, err
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:size])
	if err != nil {
		return nil, err
	}
	var fds []int
	for _, msg := range msgs {
		rights, err := unix.ParseUnixRights(&msg)
		if err != nil {
			for _, fd := range fds {
				_ = unix.Close(fd)
			}
			return nil, err
		}
		fds = append(fds, rights...)
	}
	if flags&unix.MSG_CTRUNC != 0 {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
		return nil, errors.New("truncated TUN handoff")
	}
	for _, fd := range fds {
		unix.CloseOnExec(fd)
	}
	return fds, nil
}

func (d *Daemon) attachNetwork(s *Session) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	ns := fmt.Sprintf("/proc/%d/ns/", s.SydPID)
	// Syd sets up namespaces asynchronously after Start; wait until the
	// namespace differs from the daemon's. Never create a TUN in the host.
	host, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return err
	}
	for {
		netns, err := os.Readlink(ns + "net")
		if err != nil {
			return err
		}
		if netns != host {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	out, err := exec.CommandContext(ctx, "nsenter", "--user="+ns+"user", "--net="+ns+"net", "--preserve-credentials", "--", exe, "net-attach", s.ID).CombinedOutput()
	if err != nil {
		return fmt.Errorf("network namespace setup: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// NetworkAttach runs outside the sandbox, inside ONLY its user/net namespaces.
// The state directory and the daemon Unix socket remain outside the sandbox's
// mount namespace. No privileges or TUN fd are given to the agent.
func NetworkAttach(id string) error {
	if id == "" || strings.ContainsAny(id, "/.") {
		return errors.New("bad session id")
	}
	data, err := os.ReadFile(filepath.Join(sessionsDir(), id+".json"))
	if err != nil {
		return err
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s.ID != id || !s.Network || s.SydPID <= 0 {
		return errors.New("not a network session")
	}
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	ifr, err := unix.NewIfreq("sg0")
	if err != nil {
		return err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(int(f.Fd()), unix.TUNSETIFF, ifr); err != nil {
		return fmt.Errorf("create session TUN: %w", err)
	}
	commands := [][]string{
		{"link", "set", "lo", "up"},
		{"link", "set", "sg0", "mtu", "1500", "up"},
		{"addr", "replace", "192.0.2.1/32", "dev", "sg0"},
		{"-6", "addr", "replace", "fd52::1/128", "dev", "sg0", "nodad"},
		{"route", "replace", "default", "dev", "sg0"},
		{"-6", "route", "replace", "default", "dev", "sg0"},
	}
	for _, args := range commands {
		cmd := exec.Command("ip", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("ip %v: %w: %s", args, err, out)
		}
	}
	fds := []int{int(f.Fd())}
	var files []*os.File
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()
	for _, port := range s.LocalPorts {
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
		if err != nil {
			return err
		}
		lf, err := l.File()
		_ = l.Close()
		if err != nil {
			return err
		}
		files = append(files, lf)
		fds = append(fds, int(lf.Fd()))
		ua, _ := net.ResolveUDPAddr("udp", addr)
		p, err := net.ListenUDP("udp", ua)
		if err != nil {
			return err
		}
		pf, err := p.File()
		_ = p.Close()
		if err != nil {
			return err
		}
		files = append(files, pf)
		fds = append(fds, int(pf.Fd()))
	}
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: tunSocket(id), Net: "unix"})
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, _, err := c.WriteMsgUnix([]byte{1}, unix.UnixRights(fds...), nil); err != nil {
		return err
	}
	b := make([]byte, 2)
	size, err := c.Read(b)
	if err != nil {
		return err
	}
	if string(b[:size]) != "ok" {
		return errors.New("TUN handoff refused")
	}
	return nil
}

func (n *network) HandleTCP(c adapter.TCPConn) {
	select {
	case n.flows <- struct{}{}:
		go func() { defer func() { <-n.flows }(); n.tcp(c, c.LocalAddr().String()) }()
	default:
		_ = c.Close()
	}
}

func (n *network) HandleUDP(c adapter.UDPConn) {
	select {
	case n.flows <- struct{}{}:
		go func() { defer func() { <-n.flows }(); n.udp(c, c.LocalAddr().String()) }()
	default:
		_ = c.Close()
	}
}

func (n *network) localTCP(l net.Listener, port int) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		select {
		case n.flows <- struct{}{}:
			go func() { defer func() { <-n.flows }(); n.tcp(c, net.JoinHostPort(networkGateway, strconv.Itoa(port))) }()
		default:
			_ = c.Close()
		}
	}
}

func (n *network) localUDP(p net.PacketConn, port int) {
	// Local UDP helpers are explicit grants. One bounded exchange per request
	// keeps peer addresses isolated; arbitrary internet UDP uses full flows.
	b := make([]byte, 65535)
	for {
		size, from, err := p.ReadFrom(b)
		if err != nil {
			return
		}
		q := append([]byte(nil), b[:size]...)
		select {
		case n.flows <- struct{}{}:
			go func() {
				defer func() { <-n.flows }()
				c, err := net.DialTimeout("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
				if err != nil {
					return
				}
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err := c.Write(q); err != nil {
					return
				}
				reply := make([]byte, 65535)
				size, err := c.Read(reply)
				if err == nil {
					_, _ = p.WriteTo(reply[:size], from)
				}
			}()
		default:
		}
	}
}

// NetworkWait is the sandbox's first command. It cannot configure networking;
// it just waits for the daemon-owned TUN to be ready before execing the agent.
func NetworkWait(proxy string, args []string) error {
	if len(args) == 0 {
		return errors.New("missing command")
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", proxy, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return syscall.Exec(args[0], args, os.Environ())
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("session network did not become ready")
}
