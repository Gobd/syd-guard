//go:build linux || darwin

package managedstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCreateCredential(t *testing.T) {
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		t.Skip("client requires an unprivileged user")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // directory access requires execute permission
		t.Fatal(err)
	}
	path := filepath.Join(dir, "credential")
	if err := CreateCredential(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 64 {
		t.Fatalf("credential length = %d", len(data))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("credential mode = %v", info.Mode())
	}
	if err := CreateCredential(path); err == nil {
		t.Fatal("overwrote credential")
	}
	if err := os.Link(path, path+"-alias"); err != nil {
		t.Fatal(err)
	}
	c := &Client{credentialFile: path}
	if _, err := c.credential(); err == nil {
		t.Fatal("accepted a credential with multiple links")
	}
}

func TestCreateCredentialRejectsUnprivateDirectory(t *testing.T) {
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		t.Skip("client requires an unprivileged user")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // deliberate insecure-directory test
		t.Fatal(err)
	}
	if err := CreateCredential(filepath.Join(dir, "credential")); err == nil {
		t.Fatal("accepted non-private directory")
	}
}

func TestMutationCancellationIsIndeterminate(t *testing.T) {
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		t.Skip("client requires an unprivileged user")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // private directory needs owner search permission
		t.Fatal(err)
	}
	path := filepath.Join(dir, "credential")
	if err := CreateCredential(path); err != nil {
		t.Fatal(err)
	}
	c := &Client{credentialFile: path}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Create(ctx, "registration", "test"); !errors.Is(err, ErrIndeterminate) {
		t.Fatalf("mutation error = %v", err)
	}
	if _, err := c.Read(ctx, "registration", "test"); errors.Is(err, ErrIndeterminate) || err == nil {
		t.Fatalf("read error = %v", err)
	}
	if !errors.Is(&ClientError{Code: "indeterminate", Message: "uncertain"}, ErrIndeterminate) {
		t.Fatal("server indeterminate not typed")
	}
}
