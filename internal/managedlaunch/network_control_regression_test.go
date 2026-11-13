package managedlaunch

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

type zeroControlWriter struct{}

func (zeroControlWriter) Write([]byte) (int, error) { return 0, nil }

type fragmentControlWriter struct{ bytes.Buffer }

func (w *fragmentControlWriter) Write(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return w.Buffer.Write(p)
}

func TestNetworkControlRejectsTrailingAndMalformedNumbers(t *testing.T) {
	var b bytes.Buffer
	if err := WriteNetworkControl(&b, controlFixture()); err != nil {
		t.Fatal(err)
	}
	body := string(b.Bytes()[4:])
	for _, payload := range []string{body + "{}", strings.Replace(body, `"epoch":1`, `"epoch":01`, 1), strings.Replace(body, `"pid":42`, `"pid":42.0`, 1), strings.Replace(body, `"sequence":0`, `"sequence":-1`, 1)} {
		var packet bytes.Buffer
		_ = binary.Write(&packet, binary.BigEndian, uint32(len(payload)))
		_, _ = io.WriteString(&packet, payload)
		if _, err := ReadNetworkControl(&packet); err == nil {
			t.Fatalf("accepted %s", payload)
		}
	}
	if err := WriteNetworkControl(zeroControlWriter{}, controlFixture()); err != io.ErrShortWrite {
		t.Fatalf("zero writer: %v", err)
	}
	var fragmented fragmentControlWriter
	if err := WriteNetworkControl(&fragmented, controlFixture()); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadNetworkControl(&fragmented.Buffer); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkPeerTrackerRejectsEveryBindingAndOverflow(t *testing.T) {
	expected := controlFixture()
	changes := []func(*NetworkControlFrame){
		func(f *NetworkControlFrame) { f.Nonce = strings.Repeat("f", 64) },
		func(f *NetworkControlFrame) { f.ProjectID = strings.Repeat("f", 64) },
		func(f *NetworkControlFrame) { f.ProfileName = "other" },
		func(f *NetworkControlFrame) { f.Revision = strings.Repeat("f", 64) },
		func(f *NetworkControlFrame) { f.Generation = strings.Repeat("f", 64) },
		func(f *NetworkControlFrame) { f.PID++ },
		func(f *NetworkControlFrame) { f.StartIdentity = "different" },
		func(f *NetworkControlFrame) { f.AttributesDigest = strings.Repeat("f", 64) },
		func(f *NetworkControlFrame) { f.Role = "supervisor" },
		func(f *NetworkControlFrame) { f.Epoch = 2 },
		func(f *NetworkControlFrame) { f.Version = 2 },
	}
	for _, change := range changes {
		tracker, err := NewNetworkPeerTracker(expected)
		if err != nil {
			t.Fatal(err)
		}
		wrong := expected
		change(&wrong)
		if tracker.Accept(wrong) == nil {
			t.Fatalf("accepted %+v", wrong)
		}
	}
	tracker, err := NewNetworkPeerTracker(expected)
	if err != nil {
		t.Fatal(err)
	}
	if err := tracker.Accept(expected); err != nil {
		t.Fatal(err)
	}
	tracker.sequence = ^uint64(0)
	heartbeat := expected
	heartbeat.Kind = "heartbeat"
	heartbeat.Sequence = 1
	if tracker.Accept(heartbeat) == nil {
		t.Fatal("accepted sequence overflow")
	}
}
