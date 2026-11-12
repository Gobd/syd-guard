package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxProfileBytes = 1024 * 1024

// ProfileSnapshot owns the exact validated bytes and revision reviewed by an
// operator. It provides no filesystem protection or authorization by itself.
type ProfileSnapshot struct {
	data     []byte
	revision string
}

// ParseProfileSnapshot validates an immutable copy, including duplicate keys.
func ParseProfileSnapshot(name string, data []byte) (ProfileSnapshot, error) {
	if err := ProfileName(name); err != nil {
		return ProfileSnapshot{}, err
	}
	if len(data) > maxProfileBytes {
		return ProfileSnapshot{}, fmt.Errorf("profile exceeds 1 MiB")
	}
	if !utf8.Valid(data) {
		return ProfileSnapshot{}, fmt.Errorf("profile is not valid UTF-8")
	}
	data = bytes.Clone(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := checkJSONValue(decoder, 0); err != nil {
		return ProfileSnapshot{}, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ProfileSnapshot{}, fmt.Errorf("profile contains trailing data")
	}
	var profile Profile
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		if strings.Contains(err.Error(), `unknown field "capabilities"`) {
			return ProfileSnapshot{}, fmt.Errorf("legacy capabilities field is unsupported; migrate to access values read, write, delete")
		}
		return ProfileSnapshot{}, err
	}
	if err := validateProfileFields(data); err != nil {
		return ProfileSnapshot{}, err
	}
	if err := ValidateProfile(name, profile); err != nil {
		return ProfileSnapshot{}, err
	}
	digest := sha256.Sum256(data)
	return ProfileSnapshot{data: data, revision: hex.EncodeToString(digest[:])}, nil
}

func checkJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return fmt.Errorf("profile JSON nesting is too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] || strings.ToLower(name) != name {
				return fmt.Errorf("duplicate or invalid JSON key")
			}
			seen[name] = true
			if err := checkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := checkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
	_, err = decoder.Token()
	return err
}

func (s ProfileSnapshot) Revision() string { return s.revision }
func (s ProfileSnapshot) Bytes() []byte    { return bytes.Clone(s.data) }
func (s ProfileSnapshot) Profile() Profile {
	var result Profile
	_ = json.Unmarshal(s.data, &result) // bytes were already strictly validated
	return result
}

// ValidateProfile checks only durable logical intent; it grants no access.
func ValidateProfile(name string, p Profile) error {
	if ProfileName(name) != nil || p.Version != 1 || p.Name != name || len(p.Files)+len(p.Network) > 4096 {
		return fmt.Errorf("invalid profile version/name/rule count")
	}
	for _, rule := range p.Files {
		if rule.Path == "" || filepath.Clean(rule.Path) == "/" || len(rule.Path) > 4096 || strings.ContainsAny(rule.Path, "*?[]{}\\$;!") || strings.IndexFunc(rule.Path, unicode.IsControl) >= 0 || hasParentComponent(rule.Path) || strings.HasPrefix(rule.Path, "~") && rule.Path != "~" && !strings.HasPrefix(rule.Path, "~/") || len(rule.Access) == 0 || len(rule.Access) > 3 {
			return fmt.Errorf("invalid literal file rule")
		}
		seen := map[string]bool{}
		for _, cap := range rule.Access {
			switch cap {
			case "read", "write", "delete":
			default:
				return fmt.Errorf("unsupported filesystem access %q", cap)
			}
			if seen[cap] {
				return fmt.Errorf("duplicate filesystem access")
			}
			seen[cap] = true
		}
	}
	for _, rule := range p.Network {
		if rule.Port == 0 || rule.Transport != "tcp" && rule.Transport != "udp" || !validProfileHost(rule.Host) {
			return fmt.Errorf("invalid exact network rule")
		}
	}
	return nil
}

func hasParentComponent(path string) bool {
	for _, part := range strings.Split(path, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

func validProfileHost(host string) bool {
	if len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// MergeProfile adds reviewed logical rules without modifying either input.
// It never persists rules and must only be used for an explicit saved decision.
func MergeProfile(base ProfileSnapshot, files []FileRule, network []NetworkRule) (ProfileSnapshot, error) {
	if base.revision == "" {
		return ProfileSnapshot{}, fmt.Errorf("missing reviewed base revision")
	}
	p := base.Profile()
	p.Files = append(p.Files, files...)
	p.Network = append(p.Network, network...)
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return ProfileSnapshot{}, err
	}
	return ParseProfileSnapshot(p.Name, append(data, '\n'))
}
