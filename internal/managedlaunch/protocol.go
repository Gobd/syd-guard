// Package managedlaunch defines the narrow, experimental selected-profile launch contract.
package managedlaunch

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Gobd/syd-guard/internal/config"
)

const (
	Limit = 2 * 1024 * 1024
	// FixedEnginePath is a separately installed root-owned static upstream Syd.
	FixedEnginePath = "/usr/local/libexec/sydguard-syd-3.59.0"
)

// Request is sent to the fixed privileged helper over stdin, never argv or env.
type Request struct {
	Credential string   `json:"credential"`
	ProjectID  string   `json:"project_id"`
	Name       string   `json:"name"`
	Revision   string   `json:"revision"`
	Engine     string   `json:"engine"`
	Home       string   `json:"home"`
	ConfigHome string   `json:"config_home"`
	Args       []string `json:"args"`
	RequirePIE bool     `json:"require_pie"`
}

func hexID(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == value
}

func (r Request) Validate() error {
	if !hexID(r.Credential) || !hexID(r.ProjectID) || !hexID(r.Revision) || config.ProfileName(r.Name) != nil {
		return errors.New("invalid managed launch selection")
	}
	if r.Engine != FixedEnginePath {
		return errors.New("selected replay requires the fixed immutable Syd installation")
	}
	for _, path := range []string{r.Engine, r.Home, r.ConfigHome} {
		if !utf8.ValidString(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 || strings.ContainsRune(path, 0) {
			return errors.New("launch paths must be absolute and clean")
		}
	}
	if len(r.Args) == 0 || len(r.Args) > 256 {
		return errors.New("invalid launch argument count")
	}
	for _, arg := range r.Args {
		if !utf8.ValidString(arg) || len(arg) > 32768 || strings.ContainsRune(arg, 0) {
			return errors.New("invalid launch argument")
		}
	}
	if r.Args[0] == "" {
		return errors.New("empty executable")
	}
	return nil
}

// DecodeRequest rejects duplicate keys, unknown fields, trailing data and excess input.
func DecodeRequest(input io.Reader) (Request, error) {
	var r Request
	data, err := io.ReadAll(io.LimitReader(input, Limit+1))
	if err != nil || len(data) > Limit || !utf8.Valid(data) {
		return r, errors.New("invalid or oversized launch request")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return r, errors.New("launch request must be an object")
	}
	fields := map[string]bool{}
	allowed := map[string]bool{"credential": true, "project_id": true, "name": true, "revision": true, "engine": true, "home": true, "config_home": true, "args": true, "require_pie": true}
	for d.More() {
		tok, err = d.Token()
		key, ok := tok.(string)
		if err != nil || !ok || !allowed[key] || fields[key] {
			return r, errors.New("invalid or duplicate launch field")
		}
		fields[key] = true
		var value json.RawMessage
		if err := d.Decode(&value); err != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return r, errors.New("invalid launch field value")
		}
	}
	if _, err := d.Token(); err != nil {
		return r, err
	}
	if _, err := d.Token(); err != io.EOF {
		return r, errors.New("trailing launch data")
	}
	if len(fields) != 9 {
		return r, errors.New("incomplete launch request")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&r); err != nil {
		return r, fmt.Errorf("invalid launch request: %w", err)
	}
	return r, r.Validate()
}

// ValidateIntent accepts only literal, project-relative file intent and no network.
// The boolean determines whether the pinned project bind must be writable.
func ValidateIntent(profile config.Profile) (bool, error) {
	if len(profile.Network) != 0 {
		return false, errors.New("saved network rules are unsupported by this no-network launcher")
	}
	writable := false
	for _, rule := range profile.Files {
		if rule.Path == "" || len(rule.Path) > 4096 || !utf8.ValidString(rule.Path) || strings.ContainsAny(rule.Path, "*?[]{}\\$;!") || strings.IndexFunc(rule.Path, unicode.IsControl) >= 0 || filepath.IsAbs(rule.Path) || strings.HasPrefix(rule.Path, "~") || filepath.Clean(rule.Path) != rule.Path || rule.Path == ".." || strings.HasPrefix(rule.Path, ".."+string(filepath.Separator)) {
			return false, errors.New("only clean project-relative file rules are supported")
		}
		seen := map[string]bool{}
		for _, access := range rule.Access {
			if seen[access] || (access != "read" && access != "write" && access != "delete") {
				return false, errors.New("invalid file access")
			}
			seen[access] = true
			writable = writable || access == "write" || access == "delete"
		}
		if len(seen) == 0 {
			return false, errors.New("empty file access")
		}
	}
	return writable, nil
}

// SelectedProfile resolves reviewed intent only inside the pinned project view.
func SelectedProfile(snapshot config.ProfileSnapshot, project string) (config.ResolvedProfile, error) {
	if _, err := ValidateIntent(snapshot.Profile()); err != nil {
		return config.ResolvedProfile{}, err
	}
	return config.ResolveProfile(snapshot, project, "", []string{project}, nil)
}
