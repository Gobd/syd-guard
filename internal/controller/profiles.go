package controller

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/syd"
)

// ProfileProvider is a trusted managed-store integration point. ReadSnapshot and
// Replace must return the exact helper-owned bytes, never reopen a caller-owned
// path as authority. Replace must atomically compare and replace under the helper's
// authorization and return ErrProfileConflict when the revision differs.
// IDs and project bindings must come from helper registration, not display names.
// No production managed provider is currently installed.
type ProfileProvider interface {
	List(context.Context) ([]ProfileSource, error)
	ReadSnapshot(context.Context, string) (ProfileSource, []byte, error)
	Replace(context.Context, string, string, []byte) (ProfileSource, []byte, error)
}

type ProfileSource struct {
	ID      string
	Name    string
	Project string
	Path    string
	Edit    bool
}

type ProfileCapabilities struct {
	Edit           bool `json:"edit"`
	Reload         bool `json:"reload"`
	SavedDecisions bool `json:"saved_decisions"`
}
type ProfileMetadata struct {
	ID           string              `json:"id"`
	Name         string              `json:"name"`
	Project      string              `json:"project"`
	Path         string              `json:"path"`
	Revision     string              `json:"revision"`
	Capabilities ProfileCapabilities `json:"capabilities"`
	Authority    string              `json:"authority,omitempty"`
	Description  string              `json:"description,omitempty"`
}
type ProfileRecord struct {
	ProfileMetadata
	Profile config.Profile `json:"profile"`
}
type profileOutcome struct {
	Status          string        `json:"status"`
	Profile         ProfileRecord `json:"profile"`
	Applied         bool          `json:"applied"`
	RetryRequired   bool          `json:"retry_required"`
	RestartRequired bool          `json:"restart_required"`
	Message         string        `json:"message"`
}

type profileError struct {
	Error           string `json:"error"`
	Code            string `json:"code"`
	CurrentRevision string `json:"current_revision,omitempty"`
}

func profileFailure(w http.ResponseWriter, status int, code, message, revision string) {
	reply(w, status, profileError{message, code, revision})
}

func validProfileID(id string) bool {
	if len(id) < 1 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
			continue
		}
		return false
	}
	return true
}

func safeProfileSource(s ProfileSource) bool {
	if !validProfileID(s.ID) || config.ProfileName(s.Name) != nil || !filepath.IsAbs(s.Project) || !filepath.IsAbs(s.Path) {
		return false
	}
	for _, v := range []string{s.Project, s.Path} {
		if len(v) > 4096 || !utf8.ValidString(v) || strings.IndexFunc(v, unicode.IsControl) >= 0 {
			return false
		}
	}
	return true
}

func recordFromSource(s ProfileSource, data []byte, candidate bool) (ProfileRecord, error) {
	if !safeProfileSource(s) {
		return ProfileRecord{}, fmt.Errorf("invalid profile metadata")
	}
	snapshot, err := config.ParseManagedProfileSnapshot(s.Name, data)
	if err != nil {
		return ProfileRecord{}, err
	}
	metadata := ProfileMetadata{ID: s.ID, Name: s.Name, Project: s.Project, Path: s.Path, Revision: snapshot.Revision(), Capabilities: ProfileCapabilities{Edit: s.Edit && !candidate}}
	if candidate {
		metadata.Authority = "untrusted-candidate"
		metadata.Description = "Discovered candidate; not applied to this session"
	}
	return ProfileRecord{metadata, snapshot.Profile()}, nil
}

// candidates is limited to the default profile found from active registered
// projects. Its opaque IDs are ephemeral and carry no managed-store authority.
func (server *Server) candidates() map[string]ProfileRecord {
	server.profilesMu.Lock()
	defer server.profilesMu.Unlock()
	result := map[string]ProfileRecord{}
	next := map[string]string{}
	sessions := server.registry.List(false)
	if len(sessions) > 128 {
		sessions = sessions[:128]
	}
	for _, session := range sessions {
		project, err := filepath.EvalSymlinks(session.Project)
		if err != nil || !filepath.IsAbs(project) || protectedCandidateProject(session.Project) || protectedCandidateProject(project) {
			continue
		}
		selected, err := config.SelectProfile(project, "default", false)
		if err != nil || selected.SHA256 == "" || protectedCandidateProject(selected.Path) {
			continue
		}
		// ReadProfile already validates bounded, non-symlink files. Its snapshot is
		// untrusted and is not used as a managed helper snapshot.
		key := project + "\x00" + selected.Path
		id := server.candidateIDs[key]
		if id == "" {
			var b [16]byte
			if _, err = rand.Read(b[:]); err != nil {
				continue
			}
			id = hex.EncodeToString(b[:])
		}
		source := ProfileSource{ID: id, Name: "default", Project: session.Project, Path: selected.Path}
		raw, err := json.Marshal(selected.Profile)
		if err != nil {
			continue
		}
		record, err := recordFromSource(source, raw, true)
		if err != nil {
			continue
		}
		record.Revision = selected.SHA256
		next[key] = id
		result[id] = record
	}
	server.candidateIDs = next
	return result
}

func protectedCandidateProject(path string) bool {
	if syd.ProtectedPath(path, "read", "") {
		return true
	}
	var protected []string
	if p, err := config.Path(); err == nil {
		protected = append(protected, filepath.Dir(p))
	}
	if p, err := config.StateDirectory(); err == nil {
		protected = append(protected, p)
	}
	if p, err := StateDirectory(); err == nil {
		protected = append(protected, p)
	}
	for _, root := range protected {
		if resolved, err := filepath.EvalSymlinks(root); err == nil {
			root = resolved
		}
		rel, err := filepath.Rel(root, path)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func (server *Server) profileList(w http.ResponseWriter, r *http.Request) {
	server.reap()
	records := server.candidates()
	list := make([]ProfileMetadata, 0, len(records))
	for _, record := range records {
		list = append(list, record.ProfileMetadata)
	}
	if server.profiles != nil {
		sources, err := server.profiles.List(r.Context())
		if err != nil || len(sources) > 128 {
			profileFailure(w, 503, "unavailable", "profile provider unavailable", "")
			return
		}
		for _, s := range sources {
			if _, exists := records[s.ID]; exists {
				profileFailure(w, 503, "unavailable", "profile identity collision", "")
				return
			}
			source, data, err := server.profiles.ReadSnapshot(r.Context(), s.ID)
			if err != nil || source.ID != s.ID {
				profileFailure(w, 503, "unavailable", "profile provider unavailable", "")
				return
			}
			record, err := recordFromSource(source, data, false)
			if err != nil {
				profileFailure(w, 503, "unavailable", "invalid provider snapshot", "")
				return
			}
			list = append(list, record.ProfileMetadata)
		}
	}
	reply(w, 200, list)
}

func (server *Server) readProfile(ctx context.Context, id string) (ProfileRecord, bool, error) {
	server.reap()
	if !validProfileID(id) {
		return ProfileRecord{}, false, fmt.Errorf("invalid profile id")
	}
	if record, ok := server.candidates()[id]; ok {
		return record, true, nil
	}
	if server.profiles == nil {
		return ProfileRecord{}, false, fmt.Errorf("unknown profile")
	}
	s, data, err := server.profiles.ReadSnapshot(ctx, id)
	if err != nil || s.ID != id {
		return ProfileRecord{}, false, fmt.Errorf("profile unavailable")
	}
	record, err := recordFromSource(s, data, false)
	return record, false, err
}

func (server *Server) profileGet(w http.ResponseWriter, r *http.Request) {
	record, _, err := server.readProfile(r.Context(), r.PathValue("id"))
	if err != nil {
		profileFailure(w, 404, "unavailable", "profile unavailable", "")
		return
	}
	reply(w, 200, record)
}

func (server *Server) profileSave(w http.ResponseWriter, r *http.Request) {
	record, candidate, err := server.readProfile(r.Context(), r.PathValue("id"))
	if err != nil {
		profileFailure(w, 404, "unavailable", "profile unavailable", "")
		return
	}
	if candidate || !record.Capabilities.Edit || server.profiles == nil {
		profileFailure(w, 501, "unsupported", "profile editing unavailable", "")
		return
	}
	var input struct {
		ExpectedRevision string          `json:"expected_revision"`
		Profile          json.RawMessage `json:"profile"`
	}
	if err := decodeProfileRequest(w, r, &input); err != nil {
		profileFailure(w, 422, "invalid_profile", "invalid profile request", "")
		return
	}
	snapshot, err := config.ParseManagedProfileSnapshot(record.Name, input.Profile)
	if err != nil {
		profileFailure(w, 422, "invalid_profile", "invalid profile", "")
		return
	}
	if input.ExpectedRevision != record.Revision {
		profileFailure(w, 409, "revision_conflict", "profile revision changed", record.Revision)
		return
	}
	source, data, err := server.profiles.Replace(r.Context(), record.ID, input.ExpectedRevision, snapshot.Bytes())
	if errors.Is(err, config.ErrProfileConflict) {
		current, _, readErr := server.readProfile(r.Context(), record.ID)
		revision := ""
		if readErr == nil {
			revision = current.Revision
		}
		profileFailure(w, 409, "revision_conflict", "profile revision changed", revision)
		return
	}
	if err != nil || source.ID != record.ID || source.Name != record.Name || source.Project != record.Project || source.Path != record.Path {
		profileFailure(w, 503, "unavailable", "profile replacement unavailable", "")
		return
	}
	updated, err := recordFromSource(source, data, false)
	if err != nil || updated.Revision != snapshot.Revision() {
		profileFailure(w, 503, "unavailable", "invalid replacement snapshot", "")
		return
	}
	reply(w, 200, profileOutcome{Status: "saved", Profile: updated, Message: "Saved; running permissions are unchanged."})
}

func (server *Server) profileReload(w http.ResponseWriter, r *http.Request) {
	_, _, err := server.readProfile(r.Context(), r.PathValue("id"))
	if err != nil {
		profileFailure(w, 404, "unavailable", "profile unavailable", "")
		return
	}
	profileFailure(w, 501, "unsupported", "profile reload is not available; running permissions are unchanged", "")
}

// Reject duplicate keys, invalid UTF-8, unknown fields and trailing JSON before
// decoding a profile request. The nested profile has its own strict validator.
func decodeProfileRequest(w http.ResponseWriter, r *http.Request, target any) error {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024*1024+4096))
	if err != nil || !utf8.Valid(data) {
		return fmt.Errorf("invalid JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err = checkRequestValue(decoder, 0); err != nil {
		return err
	}
	if _, err = decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing data")
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func checkRequestValue(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return fmt.Errorf("nesting too deep")
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
			token, err = decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok || seen[key] || strings.ToLower(key) != key {
				return fmt.Errorf("duplicate or invalid key")
			}
			seen[key] = true
			if err = checkRequestValue(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err = checkRequestValue(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("invalid delimiter")
	}
	_, err = decoder.Token()
	return err
}
