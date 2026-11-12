package config

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// ParseManagedProfileSnapshot requires every field of the managed wire schema,
// including explicit empty arrays and recursive flags. It does not authorize a
// profile or protect its storage; the managed store must provide both.
func ParseManagedProfileSnapshot(name string, data []byte) (ProfileSnapshot, error) {
	snapshot, err := ParseProfileSnapshot(name, data)
	if err != nil {
		return ProfileSnapshot{}, err
	}
	root, err := managedObject(data, "version", "name", "files", "network")
	if err != nil {
		return ProfileSnapshot{}, err
	}
	for _, list := range []struct {
		name   string
		fields []string
	}{
		{"files", []string{"path", "capabilities", "recursive"}},
		{"network", []string{"host", "port", "transport"}},
	} {
		var entries []json.RawMessage
		if err := json.Unmarshal(root[list.name], &entries); err != nil || entries == nil {
			return ProfileSnapshot{}, fmt.Errorf("managed profile %s must be an array", list.name)
		}
		for _, entry := range entries {
			if _, err := managedObject(entry, list.fields...); err != nil {
				return ProfileSnapshot{}, err
			}
		}
	}
	return snapshot, nil
}

func managedObject(data []byte, required ...string) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil || object == nil || len(object) != len(required) {
		return nil, fmt.Errorf("invalid managed profile object")
	}
	for _, field := range required {
		value, ok := object[field]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, fmt.Errorf("managed profile field %s is required and non-null", field)
		}
	}
	return object, nil
}
