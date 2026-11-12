//go:build linux

package managedstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/Gobd/syd-guard/internal/config"
	"golang.org/x/sys/unix"
)

// Work is bounded even for unrelated registry entries and non-profile entries:
// 4096 registry names, 256 registrations, 256 names per policy directory,
// 4096 policy names total, 128 profiles and 8 MiB of aggregate profile bytes.
const (
	maxRegistryNames   = 4096
	maxCatalogProjects = 256
	maxPolicyNames     = 256
	maxAllPolicyNames  = 4096
	maxCatalogBytes    = 8 * Limit
)

type catalogOps struct {
	registryNames func() ([]string, error)
	lookup        func(string) (registration, error)
	profiles      func(registration, int, int, int) (map[string][]byte, int, error)
	recheck       func(registration) error
}

func (s *Store) catalog() (Response, error) {
	ops := catalogOps{
		registryNames: func() ([]string, error) { return directoryNames(int(s.root.Fd()), maxRegistryNames) },
		lookup:        s.lookup,
		profiles:      s.catalogProfiles,
		recheck:       s.checkCatalogNamespace,
	}
	entries, err := collectCatalog(s.uid, ops)
	if err != nil {
		return Response{}, err
	}
	response := Response{Catalog: &entries}
	data, err := json.Marshal(response)
	if err != nil || len(data)+1 > 2*Limit+8192 {
		return Response{}, errors.New("catalog response too large")
	}
	return response, nil
}

func collectCatalog(uid int, ops catalogOps) ([]CatalogEntry, error) {
	names, err := ops.registryNames()
	if err != nil || len(names) > maxRegistryNames {
		return nil, errors.New("registry scan failed or exceeded limit")
	}
	sort.Strings(names)
	prefix := "project-" + strconv.Itoa(uid) + "-"
	regs := make([]registration, 0)
	ids := make([]string, 0)
	paths := make(map[string]bool)
	projects := make(map[[2]uint64]bool)
	policies := make(map[[2]uint64]bool)
	seen := make(map[string]bool)
	for _, name := range names {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".json")
		if !strings.HasSuffix(name, ".json") || !validProjectID(id) || seen[id] || len(regs) >= maxCatalogProjects {
			return nil, errors.New("invalid or excessive registrations")
		}
		reg, err := ops.lookup(id)
		if err != nil || ValidateProjectPath(reg.Project) != nil || reg.ProjectIno == 0 || reg.PolicyIno == 0 {
			return nil, errors.New("invalid registration")
		}
		pk, dk := [2]uint64{reg.ProjectDev, reg.ProjectIno}, [2]uint64{reg.PolicyDev, reg.PolicyIno}
		if paths[reg.Project] || projects[pk] || policies[dk] {
			return nil, errors.New("duplicate registration")
		}
		paths[reg.Project] = true
		projects[pk] = true
		policies[dk] = true
		seen[id] = true
		regs = append(regs, reg)
		ids = append(ids, id)
	}
	entries := make([]CatalogEntry, 0)
	totalBytes, totalNames := 0, 0
	for i, reg := range regs {
		profiles, scanned, err := ops.profiles(reg, maxCatalogBytes-totalBytes, min(maxPolicyNames, maxAllPolicyNames-totalNames), maxCatalogProfiles-len(entries))
		if err != nil || scanned < 0 || scanned > min(maxPolicyNames, maxAllPolicyNames-totalNames) {
			return nil, errors.New("policy scan failed or exceeded limit")
		}
		totalNames += scanned
		if totalNames > maxAllPolicyNames || len(entries)+len(profiles) > maxCatalogProfiles {
			return nil, errors.New("catalog limit exceeded")
		}
		profileNames := make([]string, 0, len(profiles))
		for name := range profiles {
			profileNames = append(profileNames, name)
		}
		sort.Strings(profileNames)
		for _, name := range profileNames {
			data := profiles[name]
			totalBytes += len(data)
			if totalBytes > maxCatalogBytes || len(data) > Limit || config.ProfileName(name) != nil {
				return nil, errors.New("invalid or excessive profile")
			}
			snap, err := config.ParseManagedProfileSnapshot(name, data)
			if err != nil {
				return nil, err
			}
			ns := &ProjectNamespace{Path: reg.Project, ProjectDev: reg.ProjectDev, ProjectIno: reg.ProjectIno, PolicyDev: reg.PolicyDev, PolicyIno: reg.PolicyIno}
			entries = append(entries, CatalogEntry{Project: ids[i], Name: name, Namespace: ns, Revision: snap.Revision()})
		}
	}
	for _, reg := range regs {
		if err := ops.recheck(reg); err != nil {
			return nil, err
		}
	}
	return entries, nil
}

// Open a new file description rather than dup: directory offsets must not be shared.
func directoryNames(dir, max int) ([]string, error) {
	fd, err := unix.Openat(dir, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "directory")
	defer func() { _ = f.Close() }()
	entries, err := f.ReadDir(max + 1)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) > max {
		return nil, errors.New("directory scan limit exceeded")
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names, nil
}

func (s *Store) openCatalogPolicy(reg registration) (int, error) {
	project, err := openDirectory(reg.Project)
	if err != nil {
		return -1, err
	}
	defer func() { _ = unix.Close(project) }()
	var p, d, root unix.Stat_t
	if err := unix.Fstat(project, &p); err != nil {
		return -1, err
	}
	if err := unix.Fstat(int(s.root.Fd()), &root); err != nil {
		return -1, err
	}
	if p.Dev != reg.ProjectDev || p.Ino != reg.ProjectIno || p.Dev != root.Dev || int(p.Uid) != s.uid || p.Mode&0o022 != 0 {
		return -1, errors.New("registered project changed")
	}
	policy, err := unix.Openat(project, config.ProfileFolder, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if err := unix.Fstat(policy, &d); err != nil {
		_ = unix.Close(policy)
		return -1, err
	}
	if d.Dev != reg.PolicyDev || d.Ino != reg.PolicyIno || d.Dev != p.Dev || d.Uid != 0 || d.Mode&0o7777 != 0o755 {
		_ = unix.Close(policy)
		return -1, errors.New("registered policy changed")
	}
	return policy, nil
}

func (s *Store) checkCatalogNamespace(reg registration) error {
	fd, err := s.openCatalogPolicy(reg)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

func (s *Store) catalogProfiles(reg registration, budget, nameLimit, profileLimit int) (map[string][]byte, int, error) {
	policy, err := s.openCatalogPolicy(reg)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = unix.Close(policy) }()
	names, err := directoryNames(policy, nameLimit)
	if err != nil {
		return nil, 0, err
	}
	if len(names) > profileLimit {
		return nil, 0, errors.New("catalog profile limit exceeded")
	}
	profiles := make(map[string][]byte)
	for _, filename := range names {
		if !strings.HasSuffix(filename, ".json") {
			return nil, 0, fmt.Errorf("unexpected managed policy entry")
		}
		name := strings.TrimSuffix(filename, ".json")
		if config.ProfileName(name) != nil || len(profiles) >= maxCatalogProfiles {
			return nil, 0, errors.New("invalid policy name or count")
		}
		max := min(Limit, budget)
		data, err := readAt(policy, filename, int64(max), 0o644)
		if err != nil {
			return nil, 0, err
		}
		budget -= len(data)
		profiles[name] = data
	}
	return profiles, len(names), nil
}
