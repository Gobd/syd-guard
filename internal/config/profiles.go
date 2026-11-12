package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const ProfileFolder = ".sydguard"

type (
	FileRule struct {
		Path      string   `json:"path"`
		Access    []string `json:"access"`
		Recursive bool     `json:"recursive"`
	}
	NetworkRule struct {
		Host      string `json:"host"`
		Port      uint16 `json:"port"`
		Transport string `json:"transport"`
	}
	Profile struct {
		Version int           `json:"version"`
		Name    string        `json:"name"`
		Files   []FileRule    `json:"files"`
		Network []NetworkRule `json:"network"`
	}
	SelectedProfile struct {
		Directory string
		Path      string
		Profile   Profile
		SHA256    string
		Trusted   bool
	}
)

func ProfileName(name string) error {
	if name == "" || len(name) > 64 || name == "." || name == ".." {
		return fmt.Errorf("invalid profile name")
	}
	for _, r := range name {
		allowed := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_'
		if !allowed {
			return fmt.Errorf("profile names use letters, digits, '-' and '_' only")
		}
	}
	return nil
}

// SelectProfile finds the nearest project profile folder while walking upward.
// Missing named profiles start empty. Existing profiles are never trusted merely
// because they were discovered in a checkout.
func SelectProfile(directory, name string, create bool) (SelectedProfile, error) {
	if name == "" {
		name = "default"
	}
	if err := ProfileName(name); err != nil {
		return SelectedProfile{}, err
	}
	directory, err := filepath.Abs(directory)
	if err != nil {
		return SelectedProfile{}, err
	}
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		return SelectedProfile{}, err
	}
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() {
		return SelectedProfile{}, fmt.Errorf("profile discovery requires a directory")
	}
	root := directory
	for current := directory; ; current = filepath.Dir(current) {
		folder := filepath.Join(current, ProfileFolder)
		if info, err := os.Lstat(folder); err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return SelectedProfile{}, fmt.Errorf("project profile folder cannot be a symlink")
			}
			root = current
			break
		} else if !os.IsNotExist(err) {
			return SelectedProfile{}, err
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	folder := filepath.Join(root, ProfileFolder)
	path := filepath.Join(folder, name+".json")
	if _, err := os.Lstat(path); os.IsNotExist(err) && create {
		if err := os.MkdirAll(folder, 0o700); err != nil {
			return SelectedProfile{}, err
		}
		empty := Profile{Version: 1, Name: name, Files: []FileRule{}, Network: []NetworkRule{}}
		data, err := json.MarshalIndent(empty, "", "  ")
		if err != nil {
			return SelectedProfile{}, err
		}
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // validated profile name and selected real directory; exclusive create never follows an existing file
		if err == nil {
			_, writeErr := file.Write(append(data, '\n'))
			closeErr := file.Close()
			if writeErr != nil {
				return SelectedProfile{}, writeErr
			}
			if closeErr != nil {
				return SelectedProfile{}, closeErr
			}
		} else if !os.IsExist(err) {
			return SelectedProfile{}, err
		}
	} else if os.IsNotExist(err) {
		return SelectedProfile{
			Directory: folder,
			Path:      path,
			Profile:   Profile{Version: 1, Name: name, Files: []FileRule{}, Network: []NetworkRule{}},
		}, nil
	} else if err != nil {
		return SelectedProfile{}, err
	}
	return ReadProfile(path)
}

func ReadProfile(path string) (SelectedProfile, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return SelectedProfile{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() > 1024*1024 {
		return SelectedProfile{}, fmt.Errorf("profile must be a non-group-writable regular file under 1 MiB")
	}
	if err := checkOwner(info); err != nil {
		return SelectedProfile{}, err
	}
	file, err := os.Open(path) //nolint:gosec // untrusted discovery only; this is not a managed policy boundary
	if err != nil {
		return SelectedProfile{}, err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return SelectedProfile{}, fmt.Errorf("profile changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxProfileBytes+1))
	if err != nil {
		return SelectedProfile{}, err
	}
	name := filepath.Base(path)
	if len(name) <= len(".json") || name[len(name)-len(".json"):] != ".json" {
		return SelectedProfile{}, fmt.Errorf("invalid profile filename")
	}
	snapshot, err := ParseProfileSnapshot(name[:len(name)-len(".json")], data)
	if err != nil {
		return SelectedProfile{}, err
	}
	selected := SelectedProfile{Directory: filepath.Dir(path), Path: path, Profile: snapshot.Profile(), SHA256: snapshot.Revision()}
	selected.Trusted, err = profileTrusted(selected)
	return selected, err
}

func trustPath(profile SelectedProfile) (string, error) {
	state, err := StateDirectory()
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256([]byte(profile.Path))
	return filepath.Join(state, "profile-trust", hex.EncodeToString(hash[:])+".sha256"), nil
}

func profileTrusted(profile SelectedProfile) (bool, error) {
	path, err := trustPath(profile)
	if err != nil {
		return false, err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := privateFile(info); err != nil {
		return false, err
	}
	if info.Size() != 64 {
		return false, fmt.Errorf("invalid profile trust record")
	}
	data, err := os.ReadFile(path) //nolint:gosec // validated private trust record
	return string(data) == profile.SHA256, err
}

// TrustProfile must only be called on an explicit operator review action. A hash
// mismatch revokes automatic loading; filesystem protection is still required.
func TrustProfile(profile SelectedProfile) error {
	current, err := ReadProfile(profile.Path)
	if err != nil {
		return err
	}
	if current.SHA256 != profile.SHA256 {
		return fmt.Errorf("profile changed during review")
	}
	path, err := trustPath(profile)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("trust directory must be private")
	}
	if err := checkOwner(info); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".trust-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	if _, err := file.WriteString(profile.SHA256); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
