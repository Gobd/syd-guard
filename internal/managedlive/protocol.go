// Package managedlive defines source-only messages for a future ROOT-managed
// live session. It does not enable a launcher or expose an engine command API.
package managedlive

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/syd"
)

const Version = 2
const MaxFrame = 8 * 1024
const EngineDigest = "523122c5dcc5f3b65b68b58fd642086d80aaa76c5c2e9825efc47b1750c69d01"

type Binding struct {
	Session    string `json:"session"`
	Project    string `json:"project"`
	Profile    string `json:"profile"`
	Generation uint64 `json:"generation"`
}
type BankReceipt struct {
	Binding  Binding `json:"binding"`
	Sequence uint64  `json:"sequence"`
	Revision string  `json:"revision"`
}
type Receipt struct {
	Version      int         `json:"version"`
	RequestID    string      `json:"request_id"`
	Phase        string      `json:"phase"`
	EngineDigest string      `json:"engine_digest"`
	Bank         BankReceipt `json:"bank"`
}
type Ticket struct {
	Version    int    `json:"version"`
	Kind       string `json:"kind"`
	Ticket     string `json:"ticket"`
	Credential string `json:"credential"`
	Project    string `json:"project"`
	Profile    string `json:"profile"`
}
type Release struct {
	Version    int     `json:"version"`
	Kind       string  `json:"kind"`
	Credential string  `json:"credential"`
	Ready      Receipt `json:"ready"`
}
type ApplySaved struct {
	Version     int         `json:"version"`
	Kind        string      `json:"kind"`
	Credential  string      `json:"credential"`
	Binding     Binding     `json:"binding"`
	RequestID   string      `json:"request_id"`
	Sequence    uint64      `json:"sequence"`
	Revision    string      `json:"revision"`
	Predecessor BankReceipt `json:"predecessor"`
}
type StatusRequest struct {
	Version    int     `json:"version"`
	Kind       string  `json:"kind"`
	Credential string  `json:"credential"`
	Binding    Binding `json:"binding"`
}
type Ready struct {
	Version int     `json:"version"`
	Kind    string  `json:"kind"`
	Ticket  string  `json:"ticket"`
	Receipt Receipt `json:"receipt"`
}
type Applied struct {
	Version int     `json:"version"`
	Kind    string  `json:"kind"`
	Receipt Receipt `json:"receipt"`
}
type Status struct {
	Version int     `json:"version"`
	Kind    string  `json:"kind"`
	Receipt Receipt `json:"receipt"`
}
type Stopped struct {
	Version int     `json:"version"`
	Kind    string  `json:"kind"`
	Receipt Receipt `json:"receipt"`
	Cleanup string  `json:"cleanup"`
}

// StartupStopped correlates a terminal pre-Ready outcome to the private launch
// ticket and selected tuple in the ROOT binding, including cleanup disposition.
type StartupStopped struct {
	Version int     `json:"version"`
	Kind    string  `json:"kind"`
	Ticket  string  `json:"ticket"`
	Binding Binding `json:"binding"`
	Cleanup string  `json:"cleanup"`
}

func hexID(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func (b Binding) valid() bool {
	return hexID(b.Session) && hexID(b.Project) && config.ProfileName(b.Profile) == nil && b.Generation > 0
}
func (b Binding) BankBinding() syd.BankBinding {
	return syd.BankBinding{Session: b.Session, Project: b.Project, Profile: b.Profile, Generation: b.Generation}
}
func (b BankReceipt) valid() bool {
	return b.Binding.valid() && ((b.Sequence == 0 && b.Revision == "") || (b.Sequence > 0 && hexID(b.Revision)))
}
func (b BankReceipt) BankReceipt() syd.BankReceipt {
	return syd.BankReceipt{Binding: b.Binding.BankBinding(), Sequence: b.Sequence, Revision: b.Revision}
}
func (r Receipt) valid(phase string) bool {
	return r.Version == Version && hexID(r.RequestID) && r.Phase == phase && r.EngineDigest == EngineDigest && r.Bank.valid() && (phase == "stopped" || r.Bank.Sequence > 0)
}

func validate(v any) error {
	if v == nil || (reflect.ValueOf(v).Kind() == reflect.Ptr && reflect.ValueOf(v).IsNil()) {
		return errors.New("invalid live message")
	}
	switch m := v.(type) {
	case *Ticket:
		if m.Version == Version && m.Kind == "ticket" && hexID(m.Ticket) && hexID(m.Credential) && hexID(m.Project) && config.ProfileName(m.Profile) == nil {
			return nil
		}
	case *Release:
		if m.Version == Version && m.Kind == "release" && hexID(m.Credential) && m.Ready.valid("ready") {
			return nil
		}
	case *ApplySaved:
		if m.Version == Version && m.Kind == "apply_saved" && hexID(m.Credential) && m.Binding.valid() && hexID(m.RequestID) && hexID(m.Revision) && m.Predecessor.valid() && m.Predecessor.Binding == m.Binding && m.Sequence > 0 && m.Predecessor.Sequence != ^uint64(0) && m.Sequence == m.Predecessor.Sequence+1 {
			return nil
		}
	case *StatusRequest:
		if m.Version == Version && m.Kind == "status" && hexID(m.Credential) && m.Binding.valid() {
			return nil
		}
	case *Ready:
		if m.Version == Version && m.Kind == "ready" && hexID(m.Ticket) && m.Receipt.valid("ready") {
			return nil
		}
	case *Applied:
		if m.Version == Version && m.Kind == "applied" && m.Receipt.valid("applied") {
			return nil
		}
	case *Status:
		if m.Version == Version && m.Kind == "status_result" && (m.Receipt.valid("ready") || m.Receipt.valid("applied")) {
			return nil
		}
	case *Stopped:
		if m.Version == Version && m.Kind == "stopped" && m.Receipt.valid("stopped") && (m.Cleanup == "clean" || m.Cleanup == "quarantined") {
			return nil
		}
	case *StartupStopped:
		if m.Version == Version && m.Kind == "startup_stopped" && hexID(m.Ticket) && m.Binding.valid() && (m.Cleanup == "clean" || m.Cleanup == "quarantined") {
			return nil
		}
	}
	return errors.New("invalid live message")
}

// objectShape validates exact keys, including nested objects and duplicates.
func objectShape(d *json.Decoder, t reflect.Type) error {
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return errors.New("expected object")
	}
	fields := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		fields[strings.Split(f.Tag.Get("json"), ",")[0]] = f.Type
	}
	seen := map[string]bool{}
	for d.More() {
		tok, err = d.Token()
		k, ok := tok.(string)
		ft, exists := fields[k]
		if err != nil || !ok || !exists || seen[k] {
			return errors.New("unknown or duplicate field")
		}
		seen[k] = true
		if ft.Kind() == reflect.Struct {
			if err = objectShape(d, ft); err != nil {
				return err
			}
		} else {
			var raw json.RawMessage
			if err = d.Decode(&raw); err != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				return errors.New("invalid field")
			}
		}
	}
	if _, err = d.Token(); err != nil {
		return err
	}
	if len(seen) != len(fields) {
		return errors.New("missing field")
	}
	return nil
}

// Decode accepts a single bounded payload; framing and peer authentication are
// separate requirements and no bytes here confer authority by themselves.
func Decode(data []byte) (any, error) {
	if len(data) == 0 || len(data) > MaxFrame || !utf8.Valid(data) {
		return nil, errors.New("invalid live frame")
	}
	var header struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return nil, err
	}
	var v any
	switch header.Kind {
	case "ticket":
		v = &Ticket{}
	case "release":
		v = &Release{}
	case "apply_saved":
		v = &ApplySaved{}
	case "status":
		v = &StatusRequest{}
	case "ready":
		v = &Ready{}
	case "applied":
		v = &Applied{}
	case "status_result":
		v = &Status{}
	case "stopped":
		v = &Stopped{}
	case "startup_stopped":
		v = &StartupStopped{}
	default:
		return nil, errors.New("unknown live message")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if err := objectShape(d, reflect.TypeOf(v).Elem()); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing live data")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return nil, err
	}
	if err := validate(v); err != nil {
		return nil, err
	}
	return v, nil
}

func Encode(v any) ([]byte, error) {
	if err := validate(v); err != nil {
		return nil, err
	}
	b, err := json.Marshal(v)
	if err != nil || len(b) > MaxFrame {
		return nil, errors.New("invalid live frame")
	}
	return b, nil
}
func WriteFrame(w io.Writer, v any) error {
	b, err := Encode(v)
	if err != nil {
		return err
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(b)))
	if err = writeAll(w, h[:]); err != nil {
		return err
	}
	return writeAll(w, b)
}
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func ReadFrame(r io.Reader) (any, error) {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > MaxFrame {
		return nil, fmt.Errorf("invalid frame length")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return Decode(b)
}
