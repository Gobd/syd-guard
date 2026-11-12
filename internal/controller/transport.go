package controller

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Gobd/syd-guard/internal/config"
)

func StateDirectory() (string, error) {
	return config.StateDirectory()
}

// privateState rejects symlinks and writable ancestors below the home boundary.
func privateState(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("controller state must be absolute")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("unsafe controller state ancestor: %s", current)
		}
		if current == filepath.Clean(path) {
			if info.Mode().Perm()&0o077 != 0 {
				return fmt.Errorf("controller state must be private: %s", path)
			}
			if err := owned(info); err != nil {
				return err
			}
		}
		// /tmp and similar shared ancestors are not a supported production state root.
		if current == filepath.Dir(current) {
			break
		}
	}
	return nil
}

func operatorToken(directory string) (string, error) {
	path := filepath.Join(directory, "operator.token")
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", err
	}
	file, err := os.CreateTemp(directory, ".token-")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	_, writeErr := io.WriteString(file, hex.EncodeToString(secret[:]))
	closeErr := file.Close()
	if writeErr != nil {
		return "", writeErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if err := os.Link(file.Name(), path); err != nil && !os.IsExist(err) {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() != 64 {
		return "", fmt.Errorf("invalid private operator token")
	}
	if err := owned(info); err != nil {
		return "", err
	}
	data, err := os.ReadFile(path) //nolint:gosec // private operator-owned regular file in validated authority directory
	if err != nil {
		return "", err
	}
	if decoded, err := hex.DecodeString(string(data)); err != nil || len(decoded) != 32 {
		return "", fmt.Errorf("invalid operator token encoding")
	}
	return string(data), nil
}

// Serve holds the single-controller lock throughout its lifetime. No TCP
// listener is exposed; operator clients use a private Unix socket and token.
func Serve(ctx context.Context, directory string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("controller must run in Linux")
	}
	if err := privateState(directory); err != nil {
		return err
	}
	lock, err := lockController(directory)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	token, err := operatorToken(directory)
	if err != nil {
		return err
	}
	path := filepath.Join(directory, "controller.sock")
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to replace non-socket controller endpoint")
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close(); _ = os.Remove(path) }()
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	controller, err := New(token)
	if err != nil {
		return err
	}
	controller.state = directory
	defer controller.Close()
	server := &http.Server{Handler: controller.Handler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 120 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-done:
		}
	}()
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
