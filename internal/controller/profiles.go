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
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/managedstore"
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

// The entire catalog/save operation shares this budget, not one per helper call.
// Leave time for helper process cleanup and operator transport before UI timeout.
const ProfileOperationTimeout = 6 * time.Second

const maxProfileDisplayPath = 4096 + 1 + len(config.ProfileFolder) + 1 + 64 + len(".json")

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
	for _, field := range []struct {
		value string
		limit int
	}{{s.Project, 4096}, {s.Path, maxProfileDisplayPath}} {
		v := field.value
		if len(v) > field.limit || !utf8.ValidString(v) || strings.IndexFunc(v, unicode.IsControl) >= 0 {
			return false
		}
	}
	return true
}

// Display names and paths are part of a provider's binding, not replacement IDs.
// Edit capability may change, but a snapshot must not silently retarget an ID.
func sameProfileIdentity(a, b ProfileSource) bool {
	return a.ID == b.ID && a.Name == b.Name && a.Project == b.Project && a.Path == b.Path
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
func (server *Server) candidates(ctx context.Context) map[string]ProfileRecord {
	result := map[string]ProfileRecord{}
	if err := lockContext(ctx, &server.profilesMu); err != nil {
		return result
	}
	defer server.profilesMu.Unlock()
	next := map[string]string{}
	sessions := server.registry.List(false)
	if len(sessions) > 128 {
		sessions = sessions[:128]
	}
	for _, session := range sessions {
		if ctx.Err() != nil {
			break
		}
		// Filter stale/reused PIDs without taking teardown authority or changing
		// session state. Candidate discovery is limited to live identities.
		identity, err := server.identity(session.PID)
		if err != nil || identity != session.StartIdentity {
			continue
		}
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
	ctx, cancel := context.WithTimeout(r.Context(), ProfileOperationTimeout)
	defer cancel()
	// Session cleanup can hold gatesMu during privileged teardown; it must not
	// block intent catalog work. Candidates remain explicitly untrusted.
	records := server.candidates(ctx)
	if ctx.Err() != nil {
		profileFailure(w, 503, "unavailable", "profile catalog deadline exceeded", "")
		return
	}
	list := make([]ProfileMetadata, 0, len(records))
	for _, record := range records {
		list = append(list, record.ProfileMetadata)
	}
	if server.profiles != nil {
		sources, err := server.profiles.List(ctx)
		if err != nil || len(sources) > 128 {
			profileFailure(w, 503, "unavailable", "profile provider unavailable", "")
			return
		}
		seen := make(map[string]bool, len(sources))
		for _, s := range sources {
			if ctx.Err() != nil {
				profileFailure(w, 503, "unavailable", "profile catalog deadline exceeded", "")
				return
			}
			if !safeProfileSource(s) {
				profileFailure(w, 503, "unavailable", "invalid provider metadata", "")
				return
			}
			if _, exists := records[s.ID]; exists || seen[s.ID] {
				profileFailure(w, 503, "unavailable", "profile identity collision", "")
				return
			}
			seen[s.ID] = true
			source, data, err := server.profiles.ReadSnapshot(ctx, s.ID)
			if err != nil || !sameProfileIdentity(source, s) {
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
	if err := ctx.Err(); err != nil {
		return ProfileRecord{}, false, err
	}
	if !validProfileID(id) {
		return ProfileRecord{}, false, fmt.Errorf("invalid profile id")
	}
	candidates := server.candidates(ctx)
	if err := ctx.Err(); err != nil {
		return ProfileRecord{}, false, err
	}
	if record, ok := candidates[id]; ok {
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
	ctx, cancel := context.WithTimeout(r.Context(), ProfileOperationTimeout)
	defer cancel()
	record, _, err := server.readProfile(ctx, r.PathValue("id"))
	if err != nil {
		profileFailure(w, 404, "unavailable", "profile unavailable", "")
		return
	}
	reply(w, 200, record)
}

func (server *Server) profileSave(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), ProfileOperationTimeout)
	defer cancel()
	record, candidate, err := server.readProfile(ctx, r.PathValue("id"))
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
	if ctx.Err() != nil {
		profileFailure(w, 503, "unavailable", "profile save deadline exceeded before replacement", "")
		return
	}
	source, data, err := server.profiles.Replace(ctx, record.ID, input.ExpectedRevision, snapshot.Bytes())
	if errors.Is(err, config.ErrProfileConflict) {
		current, _, readErr := server.readProfile(ctx, record.ID)
		revision := ""
		if readErr == nil {
			revision = current.Revision
		}
		profileFailure(w, 409, "revision_conflict", "profile revision changed", revision)
		return
	}
	if errors.Is(err, managedstore.ErrIndeterminate) || ctx.Err() != nil {
		profileFailure(w, 503, "indeterminate", "Save may have committed; authenticate a fresh snapshot before retrying. Your draft must be preserved.", "")
		return
	}
	if err != nil {
		profileFailure(w, 503, "unavailable", "profile replacement unavailable", "")
		return
	}
	if !sameProfileIdentity(source, ProfileSource{ID: record.ID, Name: record.Name, Project: record.Project, Path: record.Path}) {
		profileFailure(w, 503, "indeterminate", "Save may have committed with an invalid binding; reconcile before retrying.", "")
		return
	}
	updated, err := recordFromSource(source, data, false)
	if err != nil || updated.Revision != snapshot.Revision() {
		profileFailure(w, 503, "indeterminate", "Save may have committed with an invalid snapshot; reconcile before retrying.", "")
		return
	}
	reply(w, 200, profileOutcome{Status: "saved", Profile: updated, Message: "Saved; running permissions are unchanged."})
}

func (server *Server) profileReload(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), ProfileOperationTimeout)
	defer cancel()
	_, _, err := server.readProfile(ctx, r.PathValue("id"))
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
