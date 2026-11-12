//go:build linux

package managedstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Gobd/syd-guard/internal/config"
	"golang.org/x/sys/unix"
)

func TestTransactionLockRestrictiveUmaskAndExistingMode(t *testing.T) {
	// This is ordinary-UID descriptor/mode evidence, not a privileged ownership
	// fixture. No parallel tests may share the process-global umask change.
	dir := t.TempDir()
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if lock, err := openTransactionLock(fd, false); err == nil {
		_ = unix.Close(lock)
		t.Fatal("read-only catalog created a transaction lock")
	}
	old := unix.Umask(0o600)
	lock, err := openTransactionLock(fd, true)
	unix.Umask(old)
	if err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(lock, &stat); err != nil {
		_ = unix.Close(lock)
		t.Fatal(err)
	}
	if err := unix.Close(lock); err != nil {
		t.Fatal(err)
	}
	if stat.Mode&0o7777 != 0o600 {
		t.Fatalf("umask poisoned new lock: %o", stat.Mode&0o7777)
	}
	path := filepath.Join(dir, "transactions.lock")
	if err := os.Chmod(path, 0o640); err != nil { //nolint:gosec // test-owned existing inode must not be repaired
		t.Fatal(err)
	}
	lock, err = openTransactionLock(fd, true)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(lock), "existing lock")
	if err := checkRootFile(file, 0o600); err == nil {
		_ = file.Close()
		t.Fatal("existing wrong-mode lock passed trusted validation")
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("existing lock mode changed: %v %v", info, err)
	}
	lock, err = openTransactionLock(fd, false)
	if err != nil {
		t.Fatal(err)
	}
	file = os.NewFile(uintptr(lock), "read-only lock")
	if _, err := file.WriteString("mutate"); err == nil {
		_ = file.Close()
		t.Fatal("catalog lock descriptor was writable")
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDirectoryNamesFreshAndBounded(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a", "b", "c"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	for i := 0; i < 2; i++ {
		names, err := directoryNames(fd, 3)
		if err != nil || len(names) != 3 {
			t.Fatalf("scan %d: %v %v", i, names, err)
		}
	}
	if _, err := directoryNames(fd, 2); err == nil {
		t.Fatal("accepted truncated scan")
	}
}

func TestCollectCatalogBoundedAndFailClosed(t *testing.T) {
	id := strings.Repeat("a", 64)
	prefix := "project-123-"
	reg := registration{Project: "/project", ProjectDev: 1, ProjectIno: 2, PolicyDev: 1, PolicyIno: 3}
	payload := []byte(`{"version":1,"name":"default","files":[],"network":[]}`)
	checks := 0
	ops := catalogOps{registryNames: func() ([]string, error) {
		return []string{"project-456-" + id + ".json", prefix + id + ".json", "123.credential"}, nil
	}, lookup: func(got string) (registration, error) {
		if got != id {
			t.Fatalf("looked up another UID %s", got)
		}
		return reg, nil
	}, profiles: func(registration, int, int, int) (map[string][]byte, int, error) {
		return map[string][]byte{"default": payload}, 1, nil
	}, recheck: func(registration) error { checks++; return nil }}
	got, err := collectCatalog(123, ops)
	if err != nil || len(got) != 1 || got[0].Project != id || got[0].Name != "default" || checks != 1 {
		t.Fatalf("catalog: %+v %v checks %d", got, err, checks)
	}
	ops.registryNames = func() ([]string, error) { return nil, nil }
	got, err = collectCatalog(123, ops)
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("empty catalog: %v %v", got, err)
	}
	ops.registryNames = func() ([]string, error) { return []string{prefix + id + ".json"}, nil }
	for name, change := range map[string]func(*catalogOps){
		"bad registry": func(o *catalogOps) {
			o.registryNames = func() ([]string, error) { return []string{prefix + "bad.json"}, nil }
		},
		"duplicate registration": func(o *catalogOps) {
			o.registryNames = func() ([]string, error) {
				return []string{prefix + id + ".json", prefix + strings.Repeat("b", 64) + ".json"}, nil
			}
			o.lookup = func(string) (registration, error) { return reg, nil }
		},
		"registry limit": func(o *catalogOps) {
			o.registryNames = func() ([]string, error) { return make([]string, maxRegistryNames+1), nil }
		},
		"profile scan limit": func(o *catalogOps) {
			o.profiles = func(registration, int, int, int) (map[string][]byte, int, error) { return nil, maxPolicyNames + 1, nil }
		},
		"bad profile": func(o *catalogOps) {
			o.profiles = func(registration, int, int, int) (map[string][]byte, int, error) {
				return map[string][]byte{"default": []byte("bad")}, 1, nil
			}
		},
		"profile count": func(o *catalogOps) {
			o.profiles = func(registration, int, int, int) (map[string][]byte, int, error) {
				m := map[string][]byte{}
				for i := 0; i < maxCatalogProfiles+1; i++ {
					m[strings.Repeat("a", i+1)] = payload
				}
				return m, len(m), nil
			}
		},
		"recheck": func(o *catalogOps) { o.recheck = func(registration) error { return errors.New("moved") } },
	} {
		t.Run(name, func(t *testing.T) {
			test := ops
			change(&test)
			got, err := collectCatalog(123, test)
			if err == nil || got != nil {
				t.Fatalf("partial or success: %v %v", got, err)
			}
		})
	}
}

func TestCollectCatalogLimitsAndExactRevisions(t *testing.T) {
	id := strings.Repeat("a", 64)
	reg := registration{Project: "/project", ProjectDev: 1, ProjectIno: 2, PolicyDev: 1, PolicyIno: 3}
	profiles := make(map[string][]byte)
	for i := 0; i < maxCatalogProfiles; i++ {
		name := fmt.Sprintf("profile%d", i)
		profiles[name] = []byte(fmt.Sprintf(`{"version":1,"name":%q,"files":[],"network":[]}`, name))
	}
	ops := catalogOps{
		registryNames: func() ([]string, error) { return []string{"project-123-" + id + ".json"}, nil },
		lookup:        func(string) (registration, error) { return reg, nil },
		profiles: func(_ registration, budget, scanLimit, profileLimit int) (map[string][]byte, int, error) {
			if budget != maxCatalogBytes || scanLimit != maxPolicyNames || profileLimit != maxCatalogProfiles {
				t.Fatal("wrong initial budget")
			}
			return profiles, len(profiles), nil
		},
		recheck: func(registration) error { return nil },
	}
	got, err := collectCatalog(123, ops)
	if err != nil || len(got) != maxCatalogProfiles {
		t.Fatalf("boundary: %d %v", len(got), err)
	}
	for _, entry := range got {
		snap, err := config.ParseManagedProfileSnapshot(entry.Name, profiles[entry.Name])
		if err != nil || entry.Revision != snap.Revision() {
			t.Fatalf("revision: %s %v", entry.Name, err)
		}
	}
	ops.profiles = func(registration, int, int, int) (map[string][]byte, int, error) {
		return map[string][]byte{"default": make([]byte, Limit+1)}, 1, nil
	}
	if got, err := collectCatalog(123, ops); err == nil || got != nil {
		t.Fatal("accepted oversized profile")
	}
	ops.registryNames = func() ([]string, error) {
		names := make([]string, maxCatalogProjects+1)
		for i := range names {
			names[i] = fmt.Sprintf("project-123-%064x.json", i+1)
		}
		return names, nil
	}
	ops.lookup = func(id string) (registration, error) {
		n, err := strconv.ParseUint(id[48:], 16, 64)
		if err != nil {
			return registration{}, err
		}
		return registration{Project: "/" + id, ProjectDev: 1, ProjectIno: n, PolicyDev: 2, PolicyIno: n}, nil
	}
	if got, err := collectCatalog(123, ops); err == nil || got != nil {
		t.Fatal("accepted excessive registrations")
	}
}
