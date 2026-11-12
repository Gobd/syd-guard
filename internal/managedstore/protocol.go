package managedstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

const Limit = 1024 * 1024

type Request struct {
	Operation  string `json:"operation"`
	Project    string `json:"project"`
	Name       string `json:"name,omitempty"`
	Expected   string `json:"expected_revision,omitempty"`
	Profile    []byte `json:"profile,omitempty"`
	Credential string `json:"credential"`
}

type Response struct {
	Revision string `json:"revision,omitempty"`
	Profile  []byte `json:"profile,omitempty"`
	Error    string `json:"error,omitempty"`
	Code     string `json:"code,omitempty"`
	Project  string `json:"project,omitempty"`
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
	if r.Project == "" || r.Credential == "" || r.Operation != "register" && r.Name == "" || r.Operation == "replace" && (r.Expected == "" || len(r.Profile) == 0) {
		return r, errors.New("empty field")
	}
	return r, nil
}

func decodeResponse(data []byte, operation string) (Response, error) {
	var r Response
	fields, err := strictObject(data, "revision", "profile", "error", "code", "project")
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
	case operation == "register":
		if err := requireFields(fields, "project"); err != nil || r.Project == "" {
			return r, errors.New("invalid registration response")
		}
	default:
		if err := requireFields(fields, "revision", "profile"); err != nil || r.Revision == "" || len(r.Profile) == 0 {
			return r, errors.New("invalid snapshot response")
		}
	}
	return r, nil
}
