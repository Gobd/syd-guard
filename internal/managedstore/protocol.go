package managedstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

const Limit = 1024 * 1024

const maxCatalogProfiles = 128

type Request struct {
	Operation  string `json:"operation"`
	Project    string `json:"project,omitempty"`
	Name       string `json:"name,omitempty"`
	Expected   string `json:"expected_revision,omitempty"`
	Profile    []byte `json:"profile,omitempty"`
	Credential string `json:"credential"`
}

// Snapshot identity is registry-derived, not discovered from the project path.
// It detects changes but does not pin the namespace after the helper returns.
type Response struct {
	Revision  string            `json:"revision,omitempty"`
	Profile   []byte            `json:"profile,omitempty"`
	Error     string            `json:"error,omitempty"`
	Code      string            `json:"code,omitempty"`
	Project   string            `json:"project,omitempty"` // opaque registration ID
	Name      string            `json:"name,omitempty"`
	Namespace *ProjectNamespace `json:"namespace,omitempty"`
	Catalog   *[]CatalogEntry   `json:"catalog,omitempty"`
}

// CatalogEntry is registry-derived metadata, not a pinned namespace.
type CatalogEntry struct {
	Project   string            `json:"project"`
	Name      string            `json:"name"`
	Namespace *ProjectNamespace `json:"namespace"`
	Revision  string            `json:"revision"`
}

type ProjectNamespace struct {
	Path       string `json:"path"`
	ProjectDev uint64 `json:"project_dev"`
	ProjectIno uint64 `json:"project_ino"`
	PolicyDev  uint64 `json:"policy_dev"`
	PolicyIno  uint64 `json:"policy_ino"`
}

var ErrConflict = errors.New("profile revision conflict; review current contents")

// ErrNotSubmitted means no helper process was started for this operation.
// It must never be inferred from an arbitrary transport or helper error.
var ErrNotSubmitted = errors.New("helper operation not submitted")

// ErrIndeterminate means a mutation may have committed; authenticate a read and
// compare its SHA-256 revision before retrying. Registration needs admin inspection.
var ErrIndeterminate = errors.New("operation outcome indeterminate")

// ValidateProjectPath is the common helper/client metadata syntax boundary.
// It neither resolves the path nor establishes ownership or namespace authority.
func ValidateProjectPath(path string) error {
	if len(path) > 4096 || !utf8.ValidString(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.IndexFunc(path, unicode.IsControl) >= 0 {
		return errors.New("absolute clean literal project path required")
	}
	return nil
}

// strictObject rejects JSON's duplicate-key and case-insensitive field aliases.
func strictObject(data []byte, allowed ...string) (map[string]json.RawMessage, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("object required")
	}
	fields := make(map[string]json.RawMessage)
	valid := make(map[string]bool)
	for _, field := range allowed {
		valid[field] = true
	}
	for d.More() {
		tok, err := d.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok || !valid[key] {
			return nil, errors.New("unknown field")
		}
		if _, exists := fields[key]; exists {
			return nil, errors.New("duplicate field")
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, err
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, errors.New("null field")
		}
		fields[key] = value
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	return fields, nil
}

func requireFields(fields map[string]json.RawMessage, names ...string) error {
	if len(fields) != len(names) {
		return errors.New("incorrect fields")
	}
	for _, name := range names {
		if _, ok := fields[name]; !ok {
			return fmt.Errorf("missing %s", name)
		}
	}
	return nil
}

func decodeRequest(data []byte) (Request, error) {
	var r Request
	fields, err := strictObject(data, "operation", "project", "name", "expected_revision", "profile", "credential")
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return r, err
	}
	var names []string
	switch r.Operation {
	case "catalog":
		names = []string{"operation", "credential"}
	case "register":
		names = []string{"operation", "project", "credential"}
	case "create", "read":
		names = []string{"operation", "project", "name", "credential"}
	case "replace":
		names = []string{"operation", "project", "name", "credential", "expected_revision", "profile"}
	default:
		return r, errors.New("unsupported operation")
	}
	if err := requireFields(fields, names...); err != nil {
		return r, err
	}
	if r.Credential == "" || r.Operation != "catalog" && r.Project == "" || r.Operation != "register" && r.Operation != "catalog" && r.Name == "" || r.Operation == "replace" && (r.Expected == "" || len(r.Profile) == 0) {
		return r, errors.New("empty field")
	}
	return r, nil
}

func decodeResponse(data []byte, operation string) (Response, error) {
	var r Response
	if len(data) > 2*Limit+8192 {
		return r, errors.New("response too large")
	}
	fields, err := strictObject(data, "revision", "profile", "error", "code", "project", "name", "namespace", "catalog")
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return r, err
	}
	switch {
	case r.Error != "":
		if err := requireFields(fields, "error", "code"); err != nil || r.Code == "" || len(r.Error) > 256 || len(r.Code) > 32 {
			return r, errors.New("invalid error response")
		}
	case operation == "catalog":
		if err := requireFields(fields, "catalog"); err != nil || r.Catalog == nil {
			return r, errors.New("invalid catalog response")
		}
		var entries []json.RawMessage
		if err := json.Unmarshal(fields["catalog"], &entries); err != nil || entries == nil || len(entries) > maxCatalogProfiles {
			return r, errors.New("invalid catalog entries")
		}
		for _, entry := range entries {
			f, err := strictObject(entry, "project", "name", "namespace", "revision")
			if err != nil || requireFields(f, "project", "name", "namespace", "revision") != nil || validateNamespaceWire(f["namespace"]) != nil {
				return r, errors.New("invalid catalog entry")
			}
		}
	case operation == "register":
		if err := requireFields(fields, "project"); err != nil || r.Project == "" {
			return r, errors.New("invalid registration response")
		}
	case operation == "read" || operation == "create" || operation == "replace":
		if err := requireFields(fields, "revision", "profile", "project", "name", "namespace"); err != nil || r.Revision == "" || len(r.Profile) == 0 || r.Project == "" || r.Name == "" || r.Namespace == nil {
			return r, errors.New("invalid snapshot response")
		}
		if validateNamespaceWire(fields["namespace"]) != nil || r.Namespace.ProjectIno == 0 || r.Namespace.PolicyIno == 0 {
			return r, errors.New("invalid snapshot namespace")
		}
	default:
		return r, errors.New("unsupported response operation")
	}
	return r, nil
}

func validateNamespaceWire(data []byte) error {
	fields, err := strictObject(data, "path", "project_dev", "project_ino", "policy_dev", "policy_ino")
	if err != nil || requireFields(fields, "path", "project_dev", "project_ino", "policy_dev", "policy_ino") != nil {
		return errors.New("invalid namespace")
	}
	return nil
}
