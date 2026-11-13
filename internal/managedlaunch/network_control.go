package managedlaunch

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/Gobd/syd-guard/internal/config"
)

const networkControlVersion = 1
const networkControlLimit = 8192

// NetworkControlFrame is valid only on an exclusively inherited channel whose
// child PID, start identity, executable and lifetime have been independently
// verified by root. A frame itself does not authenticate its sender.
type NetworkControlFrame struct {
	Version          int    `json:"version"`
	Kind             string `json:"kind"`
	Role             string `json:"role"`
	Nonce            string `json:"nonce"`
	ProjectID        string `json:"project_id"`
	ProfileName      string `json:"profile_name"`
	Revision         string `json:"revision"`
	Generation       string `json:"generation"`
	Epoch            uint64 `json:"epoch"`
	PID              int    `json:"pid"`
	StartIdentity    string `json:"start_identity"`
	AttributesDigest string `json:"attributes_digest"`
	Sequence         uint64 `json:"sequence"`
}

func (f NetworkControlFrame) validate() error {
	if f.Version != networkControlVersion || (f.Kind != "ready" && f.Kind != "heartbeat") || (f.Role != "broker" && f.Role != "supervisor") || !hexID(f.Nonce) || !hexID(f.ProjectID) || !hexID(f.Revision) || !hexID(f.Generation) || !hexID(f.AttributesDigest) || f.Epoch != 1 || f.PID <= 0 || !validNetworkStartIdentity(f.StartIdentity) || config.ProfileName(f.ProfileName) != nil {
		return errors.New("invalid network control frame")
	}
	if (f.Kind == "ready" && f.Sequence != 0) || (f.Kind == "heartbeat" && f.Sequence == 0) {
		return errors.New("invalid network control sequence")
	}
	return nil
}

// Process identities are root-observed opaque values; exclude delimiters and
// control bytes so canonical framing cannot hide alternative representations.
func validNetworkStartIdentity(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

func WriteNetworkControl(w io.Writer, f NetworkControlFrame) error {
	if err := f.validate(); err != nil {
		return err
	}
	data, err := json.Marshal(f)
	if err != nil || len(data) > networkControlLimit {
		return errors.New("invalid network control encoding")
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(data))) // bounded above
	for _, part := range [][]byte{size[:], data} {
		for len(part) > 0 {
			n, err := w.Write(part)
			if err != nil {
				return err
			}
			if n <= 0 || n > len(part) {
				return io.ErrShortWrite
			}
			part = part[n:]
		}
	}
	return nil
}

// ReadNetworkControl accepts one canonical, size-prefixed object. The owner of
// the private descriptor must impose a deadline and reject unexpected FDs.
func ReadNetworkControl(r io.Reader) (NetworkControlFrame, error) {
	var f NetworkControlFrame
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return f, err
	}
	n := binary.BigEndian.Uint32(size[:])
	if n == 0 || n > networkControlLimit {
		return f, errors.New("invalid network control size")
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return f, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&f); err != nil {
		return f, fmt.Errorf("invalid network control object: %w", err)
	}
	canonical, err := json.Marshal(f)
	if err != nil || !bytes.Equal(canonical, data) {
		return f, errors.New("noncanonical network control object")
	}
	if err := f.validate(); err != nil {
		return f, err
	}
	return f, nil
}

// NetworkPeerTracker binds frames to independently observed root-owned launch
// identity. It rejects duplicate ready, replayed or skipped heartbeats, and is
// not itself a scheduler, pidfd watcher or timeout implementation.
type NetworkPeerTracker struct {
	expected NetworkControlFrame
	ready    bool
	sequence uint64
}

func NewNetworkPeerTracker(expected NetworkControlFrame) (*NetworkPeerTracker, error) {
	if expected.Kind != "ready" || expected.Sequence != 0 {
		return nil, errors.New("expected ready binding required")
	}
	if err := expected.validate(); err != nil {
		return nil, err
	}
	return &NetworkPeerTracker{expected: expected}, nil
}

func (p *NetworkPeerTracker) Accept(f NetworkControlFrame) error {
	if p == nil {
		return errors.New("missing network peer tracker")
	}
	if err := f.validate(); err != nil {
		return err
	}
	want := p.expected
	want.Kind, want.Sequence = f.Kind, f.Sequence
	if f != want {
		return errors.New("network peer binding mismatch")
	}
	if !p.ready {
		if f.Kind != "ready" {
			return errors.New("ready required")
		}
		p.ready = true
		return nil
	}
	if f.Kind != "heartbeat" || p.sequence == ^uint64(0) || f.Sequence != p.sequence+1 {
		return errors.New("stale network heartbeat")
	}
	p.sequence = f.Sequence
	return nil
}
