//go:build linux

package main

import (
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Minimal ELF metadata is sufficient to test identity/interpreter checks; this
// fixture never executes its synthetic executable or performs a privileged bind.
func engineELF(interpreter bool) []byte {
	data := make([]byte, 120)
	copy(data, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(data[16:], 2)
	binary.LittleEndian.PutUint16(data[18:], 183)
	binary.LittleEndian.PutUint32(data[20:], 1)
	binary.LittleEndian.PutUint64(data[32:], 64)
	binary.LittleEndian.PutUint16(data[52:], 64)
	binary.LittleEndian.PutUint16(data[54:], 56)
	if interpreter {
		binary.LittleEndian.PutUint16(data[56:], 1)
		binary.LittleEndian.PutUint32(data[64:], 3)
	}
	return data
}

// This checks the real static engine's ELF metadata as an ordinary UID; it does
// not install, launch, bind-mount or invoke it as root.
func TestEngineStaticSydMetadataIntegration(t *testing.T) {
	path := os.Getenv("SYDGUARD_TEST_SYD")
	if path == "" {
		t.Skip("requires explicit static Syd 3.59.0")
	}
	source, err := os.Open(path) //nolint:gosec // explicit opt-in test fixture
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = source.Close() }()
	target := filepath.Join(t.TempDir(), "syd")
	//nolint:gosec // test-owned executable fixture requires owner execute
	copyFile, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(copyFile, source); err != nil {
		_ = copyFile.Close()
		t.Fatal(err)
	}
	if err := copyFile.Close(); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(target) //nolint:gosec // test-owned static ELF copy
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	owner := uint32(os.Getuid()) //nolint:gosec // Linux getuid returns a kernel uid_t
	if err := validateEngineFD(file, st, owner); err != nil {
		t.Fatal(err)
	}
}

func TestEngineIdentityRejectsReplacementSymlinkAndDynamicInterpreter(t *testing.T) {
	dir := t.TempDir()
	path, old := filepath.Join(dir, "engine"), filepath.Join(dir, "old-engine")
	//nolint:gosec // synthetic executable metadata requires its owner execute bit
	if err := os.WriteFile(path, engineELF(false), 0o700); err != nil {
		t.Fatal(err)
	}
	original, err := os.Open(path) //nolint:gosec // test-owned synthetic ELF
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = original.Close() }()
	var identity unix.Stat_t
	if err := unix.Fstat(int(original.Fd()), &identity); err != nil {
		t.Fatal(err)
	}
	owner := uint32(os.Getuid()) //nolint:gosec // Linux getuid returns a kernel uid_t
	if err := validateEngineFD(original, identity, owner); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, old); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // synthetic executable metadata requires its owner execute bit
	if err := os.WriteFile(path, engineELF(false), 0o700); err != nil {
		t.Fatal(err)
	}
	replaced, err := os.Open(path) //nolint:gosec // test-owned replacement
	if err != nil {
		t.Fatal(err)
	}
	if err := validateEngineFD(replaced, identity, owner); err == nil {
		t.Fatal("replacement inode accepted")
	}
	if err := replaced.Close(); err != nil {
		t.Fatal(err)
	}
	if err := validateEngineFD(original, identity, owner); err != nil {
		t.Fatalf("held original was lost: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(old, path); err != nil {
		t.Fatal(err)
	}
	if fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0); err == nil {
		_ = unix.Close(fd)
		t.Fatal("engine symlink accepted")
	}
	dynamic := filepath.Join(dir, "dynamic")
	//nolint:gosec // synthetic executable metadata requires its owner execute bit
	if err := os.WriteFile(dynamic, engineELF(true), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(dynamic) //nolint:gosec // test-owned synthetic ELF
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var dynamicStat unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &dynamicStat); err != nil {
		t.Fatal(err)
	}
	if err := validateEngineFD(f, dynamicStat, owner); err == nil {
		t.Fatal("ELF interpreter accepted")
	}
}
