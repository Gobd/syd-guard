package files

import "encoding/json"

// ParseEvents normalizes Syd's scalar or multi-capability event representation.
// This parser must only receive the dedicated trusted logging descriptor.
func ParseEvents(data []byte) []Event {
	var raw struct {
		Capability json.RawMessage `json:"cap"`
		Path       string          `json:"path"`
		Action     string          `json:"act"`
	}
	if json.Unmarshal(data, &raw) != nil || raw.Action != "deny" {
		return nil
	}
	var capabilities []string
	var single string
	if json.Unmarshal(raw.Capability, &single) == nil {
		capabilities = []string{single}
	} else if json.Unmarshal(raw.Capability, &capabilities) != nil {
		return nil
	}
	events := make([]Event, 0, len(capabilities))
	for _, capability := range capabilities {
		events = append(events, Event{Capability: capability, Path: raw.Path, Action: raw.Action})
	}
	return events
}
