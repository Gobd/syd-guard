package managedlaunch

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

func controlFixture() NetworkControlFrame {
	return NetworkControlFrame{Version: 1, Kind: "ready", Role: "broker", Nonce: strings.Repeat("a", 64), ProjectID: strings.Repeat("b", 64), ProfileName: "dev", Revision: strings.Repeat("c", 64), Generation: strings.Repeat("d", 64), Epoch: 1, PID: 42, StartIdentity: "12345", AttributesDigest: strings.Repeat("e", 64)}
}

func TestNetworkControlFramesRejectNoncanonicalAndPartial(t *testing.T) {
	frame := controlFixture()
	var buf bytes.Buffer
	if err := WriteNetworkControl(&buf, frame); err != nil {
		t.Fatal(err)
	}
	encoded := append([]byte(nil), buf.Bytes()...)
	decoded, err := ReadNetworkControl(bytes.NewReader(encoded))
	if err != nil || decoded != frame {
		t.Fatalf("roundtrip: %+v %v", decoded, err)
	}
	for _, data := range [][]byte{nil, encoded[:3], encoded[:len(encoded)-1], {0, 0, 0, 0}, {0xff, 0xff, 0xff, 0xff}} {
		if _, err := ReadNetworkControl(bytes.NewReader(data)); err == nil {
			t.Fatalf("accepted %x", data)
		}
	}
	payload := string(encoded[4:])
	for _, modified := range []string{
		strings.Replace(payload, `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(payload, `"version":1`, `"version":2`, 1),
		strings.Replace(payload, `"version":1`, `"unknown":1,"version":1`, 1),
		strings.Replace(payload, `"sequence":0`, `"sequence":null`, 1),
		strings.Replace(payload, `"epoch":1`, `"epoch":"1"`, 1),
		" " + payload,
	} {
		var packet bytes.Buffer
		_ = binary.Write(&packet, binary.BigEndian, uint32(len(modified)))
		_, _ = io.WriteString(&packet, modified)
		if _, err := ReadNetworkControl(&packet); err == nil {
			t.Fatalf("accepted %s", modified)
		}
	}
}

func TestNetworkPeerTrackerBindsAndRejectsReplay(t *testing.T) {
	ready := controlFixture()
	tracker, err := NewNetworkPeerTracker(ready)
	if err != nil {
		t.Fatal(err)
	}
	heartbeat := ready
	heartbeat.Kind = "heartbeat"
	heartbeat.Sequence = 1
	if err := tracker.Accept(heartbeat); err == nil {
		t.Fatal("heartbeat before ready")
	}
	wrong := ready
	wrong.PID++
	if err := tracker.Accept(wrong); err == nil {
		t.Fatal("wrong child")
	}
	wrong = ready
	wrong.Role = "supervisor"
	if err := tracker.Accept(wrong); err == nil {
		t.Fatal("wrong role")
	}
	wrong = ready
	wrong.Revision = strings.Repeat("f", 64)
	if err := tracker.Accept(wrong); err == nil {
		t.Fatal("wrong revision")
	}
	wrong = ready
	wrong.Generation = strings.Repeat("f", 64)
	if err := tracker.Accept(wrong); err == nil {
		t.Fatal("wrong generation")
	}
	wrong = ready
	wrong.AttributesDigest = strings.Repeat("f", 64)
	if err := tracker.Accept(wrong); err == nil {
		t.Fatal("wrong attributes")
	}
	if err := tracker.Accept(ready); err != nil {
		t.Fatal(err)
	}
	if err := tracker.Accept(ready); err == nil {
		t.Fatal("ready replay")
	}
	if err := tracker.Accept(heartbeat); err != nil {
		t.Fatal(err)
	}
	if err := tracker.Accept(heartbeat); err == nil {
		t.Fatal("heartbeat replay")
	}
	heartbeat.Sequence = 3
	if err := tracker.Accept(heartbeat); err == nil {
		t.Fatal("skipped heartbeat")
	}
	heartbeat.Sequence = 2
	if err := tracker.Accept(heartbeat); err != nil {
		t.Fatal(err)
	}
}
