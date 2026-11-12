//go:build linux || darwin

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/Gobd/syd-guard/internal/backend"
	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/webui"
)

const uiTokenLifetime = 30 * time.Minute

type (
	uiManager  struct{ dir, identity, guestExecutable, guestConfigHome string }
	uiMetadata struct {
		Identity string `json:"identity"`
		Nonce    string `json:"nonce"`
	}
	uiRequest struct {
		Identity string `json:"identity"`
		Nonce    string `json:"nonce"`
		Action   string `json:"action"`
	}
	uiResponse struct {
		Identity string `json:"identity"`
		Nonce    string `json:"nonce"`
		URL      string `json:"url,omitempty"`
		Version  string `json:"version,omitempty"`
		Error    string `json:"error,omitempty"`
	}
)

func newUIManager(identity string) (*uiManager, error) {
	path, err := config.Path()
	if err != nil {
		return nil, err
	}
	base := filepath.Join(filepath.Dir(path), "ui")
	if err := os.MkdirAll(base, 0o700); err != nil {
		return nil, err
	}
	// Reject symlinks and writable ancestors; a sticky shared ancestor is safe
	// only with the private, operator-owned directory checked below it.
	for p := base; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || (info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0) {
			return nil, fmt.Errorf("unsafe UI state ancestor: %s", p)
		}
		if p == base || p == filepath.Dir(path) {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || int(stat.Uid) != os.Geteuid() || info.Mode().Perm()&0o077 != 0 {
				return nil, fmt.Errorf("UI state directory must be private and operator-owned: %s", p)
			}
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	hash := sha256.Sum256([]byte(identity))
	dir := filepath.Join(base, hex.EncodeToString(hash[:12]))
	if err := os.Mkdir(dir, 0o700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !ok || int(stat.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("invalid UI identity directory")
	}
	return &uiManager{dir: dir, identity: identity}, nil
}

func (m *uiManager) lock(ctx context.Context, name string) (*os.File, error) {
	path := filepath.Join(m.dir, name)
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !ok || int(stat.Uid) != os.Geteuid() {
			err = fmt.Errorf("invalid UI lock")
		}
	}
	for err == nil {
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			break
		}
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case <-time.After(25 * time.Millisecond):
			err = nil
		}
	}
	_ = f.Close()
	return nil, err
}

func randomUISecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func (m *uiManager) readMetadata() (uiMetadata, error) {
	var meta uiMetadata
	p := filepath.Join(m.dir, "meta.json")
	info, err := os.Lstat(p)
	if err != nil {
		return meta, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 1024 || !ok || int(stat.Uid) != os.Geteuid() {
		return meta, fmt.Errorf("invalid UI metadata")
	}
	b, err := os.ReadFile(p) //nolint:gosec // private owned file in private directory
	if err != nil {
		return meta, err
	}
	if json.Unmarshal(b, &meta) != nil || meta.Identity != m.identity || len(meta.Nonce) != 64 {
		return meta, fmt.Errorf("invalid UI identity metadata")
	}
	return meta, nil
}

func (m *uiManager) request(action string) (uiResponse, error) {
	var response uiResponse
	meta, err := m.readMetadata()
	if err != nil {
		return response, err
	}
	conn, err := net.DialTimeout("unix", filepath.Join(m.dir, "s"), time.Second)
	if err != nil {
		return response, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if err := json.NewEncoder(conn).Encode(uiRequest{Identity: m.identity, Nonce: meta.Nonce, Action: action}); err != nil {
		return response, err
	}
	if err := json.NewDecoder(io.LimitReader(conn, 2048)).Decode(&response); err != nil {
		return response, err
	}
	if response.Identity != m.identity || subtle.ConstantTimeCompare([]byte(response.Nonce), []byte(meta.Nonce)) != 1 {
		return response, fmt.Errorf("UI identity handshake failed")
	}
	if response.Error != "" {
		return response, errors.New(response.Error)
	}
	return response, nil
}

func (m *uiManager) command(ctx context.Context, action string, detach bool, kind backend.Kind, instance string, out, stderr io.Writer) error {
	op, err := m.lock(ctx, "operation.lock")
	if err != nil {
		return err
	}
	defer func() {
		if op != nil {
			_ = op.Close()
		}
	}()
	response, probeErr := m.request("status")
	if probeErr == nil {
		if action == "stop" || action == "restart" {
			if _, err := m.request("stop"); err != nil {
				return err
			}
			wait, cancel := context.WithTimeout(ctx, 15*time.Second)
			life, err := m.lock(wait, "lifetime.lock")
			cancel()
			if err != nil {
				return fmt.Errorf("waiting for UI shutdown: %w", err)
			}
			_ = life.Close()
			if action == "stop" {
				_, err = fmt.Fprintln(out, "UI stopped; agent sessions and controller are unchanged.")
				return err
			}
		} else {
			_, err := fmt.Fprintf(out, "Approvals UI: %s\nUI version: %s. Keep this operator-only URL private.\n", response.URL, response.Version)
			return err
		}
	} else {
		// Never signal a PID or replace a socket when the lifetime lock is held.
		check, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		life, err := m.lock(check, "lifetime.lock")
		cancel()
		if err != nil {
			return fmt.Errorf("UI is starting or its identity handshake failed: %w", probeErr)
		}
		_ = life.Close()
		if action == "status" || action == "stop" {
			_, err := fmt.Fprintln(out, "UI is not running.")
			return err
		}
	}
	if !detach && action != "restart" {
		return runUIBridge(ctx, m, kind, instance, out, stderr, true, func() { _ = op.Close(); op = nil })
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := []string{"ui", "--managed-child", "--backend", string(kind)}
	if instance != "" {
		args = append(args, "--vm", instance)
	}
	if m.guestExecutable != "" {
		args = append(args, "--guest-sydguard", m.guestExecutable)
	}
	if m.guestConfigHome != "" {
		args = append(args, "--guest-config-home", m.guestConfigHome)
	}
	logPath := filepath.Join(m.dir, "bridge.log")
	fd, err := syscall.Open(logPath, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	log := os.NewFile(uintptr(fd), logPath)
	defer func() { _ = log.Close() }()
	info, err := log.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !ok || int(stat.Uid) != os.Geteuid() || stat.Nlink != 1 {
		return fmt.Errorf("invalid UI log file")
	}
	if err := log.Truncate(0); err != nil {
		return err
	}
	cmd := exec.Command(exe, args...) //nolint:gosec // current installed CLI and validated backend argv
	cmd.Stdin = nil
	cmd.Stdout, cmd.Stderr = log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	timer := time.NewTimer(45 * time.Second)
	defer timer.Stop()
	for {
		if response, err = m.request("status"); err == nil {
			_, err = fmt.Fprintf(out, "Approvals UI: %s\nUI version: %s. Keep this operator-only URL private.\n", response.URL, response.Version)
			return err
		}
		select {
		case err := <-exited:
			return fmt.Errorf("UI startup failed (%v); inspect private log %s", err, logPath)
		case <-timer.C:
			return fmt.Errorf("UI startup timed out; inspect private log %s", logPath)
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

type uiToken struct {
	mu      sync.Mutex
	token   string
	expires time.Time
}

func (t *uiToken) current() (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if time.Now().After(t.expires) {
		token, err := randomUISecret()
		if err != nil {
			return "", err
		}
		t.token, t.expires = token, time.Now().Add(uiTokenLifetime)
	}
	return t.token, nil
}

func (t *uiToken) authorize(value string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return time.Now().Before(t.expires) && subtle.ConstantTimeCompare([]byte(value), []byte(t.token)) == 1
}

func (m *uiManager) serve(parent context.Context, out io.Writer, foreground bool, ready func(), open func(context.Context) (webui.Operator, func(), error)) error {
	life, err := m.lock(parent, "lifetime.lock")
	if err != nil {
		return err
	}
	defer func() { _ = life.Close() }()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	operate, closeBackend, err := open(ctx)
	if err != nil {
		return err
	}
	defer closeBackend()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
	controlPath := filepath.Join(m.dir, "s")
	if info, err := os.Lstat(controlPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to replace non-socket UI endpoint")
		}
		if err := os.Remove(controlPath); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	control, err := net.Listen("unix", controlPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = control.Close()
		_ = os.Remove(controlPath)
		_ = os.Remove(filepath.Join(m.dir, "meta.json"))
	}()
	if err := os.Chmod(controlPath, 0o600); err != nil {
		return err
	}
	nonce, err := randomUISecret()
	if err != nil {
		return err
	}
	meta := uiMetadata{Identity: m.identity, Nonce: nonce}
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(m.dir, ".meta-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), filepath.Join(m.dir, "meta.json")); err != nil {
		return err
	}
	token := &uiToken{}
	if _, err := token.current(); err != nil {
		return err
	}
	host := listener.Addr().String()
	go func() {
		for {
			conn, err := control.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				var req uiRequest
				if json.NewDecoder(io.LimitReader(conn, 2048)).Decode(&req) != nil || req.Identity != m.identity || subtle.ConstantTimeCompare([]byte(req.Nonce), []byte(nonce)) != 1 {
					return
				}
				res := uiResponse{Identity: m.identity, Nonce: nonce, Version: version}
				switch req.Action {
				case "status":
					secret, err := token.current()
					if err != nil {
						res.Error = "token generation failed"
					} else {
						res.URL = "http://" + host + "/#token=" + secret
					}
				case "stop":
				default:
					res.Error = "unsupported action"
				}
				_ = json.NewEncoder(conn).Encode(res)
				if req.Action == "stop" {
					cancel()
				}
			}()
		}
	}()
	if foreground {
		secret, err := token.current()
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(out, "Approvals UI: http://%s/#token=%s\nKeep this operator-only URL private. Ctrl-C closes the UI bridge.\n", host, secret); err != nil {
			return err
		}
	}
	if ready != nil {
		ready()
	}
	return webui.ServeListener(ctx, webui.NewServer(webui.HandlerWithAuth(host, token.authorize, operate)), listener)
}
