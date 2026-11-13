//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func testLiveSealBinding() liveSealBinding {
	return liveSealBinding{UID: 502, Index: 1, Nonce: strings.Repeat("a", 64), Generation: 3, ParentPID: 17, ParentIdentity: "start-17", AnchorDev: 2, AnchorIno: 3, CgroupDev: 4, CgroupIno: 5}
}

func testLegacyForBinding(b liveSealBinding) slotJournal {
	return slotJournal{Version: 1, UID: b.UID, Index: b.Index, Nonce: b.Nonce, ParentPID: b.ParentPID, ParentIdentity: b.ParentIdentity, Phase: "ready", AnchorDev: b.AnchorDev, AnchorIno: b.AnchorIno, CgroupDev: b.CgroupDev, CgroupIno: b.CgroupIno}
}

type liveSealModel struct {
	t           *testing.T
	b           liveSealBinding
	slot        *launchSlot
	now         time.Time
	events      []string
	failure     string
	removeErr   error
	advance     map[string]time.Duration
	record      liveSealRecord
	reservation liveReservation
	legacy      slotJournal
}

func newLiveSealModel(t *testing.T) *liveSealModel {
	b := testLiveSealBinding()
	return &liveSealModel{t: t, b: b, slot: &launchSlot{UID: b.UID, Index: b.Index}, now: time.Unix(100, 0), advance: map[string]time.Duration{}, record: liveSealRecord{2, "live-cgroup-seal", b, liveSealOpen}, reservation: liveReservation{Version: 2, Kind: "live-reservation", Binding: b}, legacy: testLegacyForBinding(b)}
}
func (m *liveSealModel) event(name string) error {
	m.events = append(m.events, name)
	m.now = m.now.Add(m.advance[name])
	if m.failure == name {
		return errors.New("injected " + name)
	}
	return nil
}
func (m *liveSealModel) barrier() *liveSealBarrier {
	ops := liveSealOps{
		now: func() time.Time { return m.now },
		kill: func(fd int) error {
			if fd != 41 {
				m.t.Fatal("wrong cgroup FD")
			}
			return m.event("kill")
		},
		drain: func(fd int, deadline time.Time) error {
			if fd != 41 || !deadline.Equal(time.Unix(100, 0).Add(liveSealBudget)) {
				m.t.Fatal("wrong drain binding or deadline")
			}
			return m.event("drain")
		},
		readReservation: func() (liveReservation, bool, error) { err := m.event("reservation"); return m.reservation, true, err },
		readLegacy:      func() (slotJournal, bool, error) { err := m.event("legacy"); return m.legacy, true, err },
		readSeal:        func() (liveSealRecord, bool, error) { err := m.event("read-seal"); return m.record, true, err },
		writeSeal: func(r liveSealRecord) error {
			name := "pending"
			if r.Phase == liveSealRecorded {
				name = "sealed"
			}
			err := m.event(name)
			if err == nil {
				m.record = r
			}
			return err
		},
		checkCgroup: func() error { return m.event("identity") },
		removeCgroup: func() error {
			err := m.event("remove")
			if err != nil {
				return err
			}
			return m.removeErr
		},
	}
	return &liveSealBarrier{fd: 41, slot: m.slot, binding: m.b, ops: ops}
}
func TestLiveCgroupSealOrderAndBoundaryFailures(t *testing.T) {
	want := []string{"kill", "drain", "reservation", "legacy", "read-seal", "pending", "identity", "remove", "sealed"}
	m := newLiveSealModel(t)
	authority, err := m.barrier().seal()
	if err != nil || authority == nil || authority.binding != m.b || !reflect.DeepEqual(m.events, want) {
		t.Fatalf("authority=%v err=%v events=%v", authority, err, m.events)
	}
	for i, fail := range want {
		t.Run(fail, func(t *testing.T) {
			m := newLiveSealModel(t)
			m.failure = fail
			a, err := m.barrier().seal()
			if err == nil || a != nil || !reflect.DeepEqual(m.events, want[:i+1]) {
				t.Fatalf("authority=%v err=%v events=%v", a, err, m.events)
			}
			if i > 5 && m.record.Phase != liveSealSealing {
				t.Fatalf("expected durable pending, got %s", m.record.Phase)
			}
		})
	}
}
func TestLiveCgroupSealBusyNeverRetriesRemoval(t *testing.T) {
	m := newLiveSealModel(t)
	m.removeErr = unix.EBUSY
	a, err := m.barrier().seal()
	want := []string{"kill", "drain", "reservation", "legacy", "read-seal", "pending", "identity", "remove", "kill"}
	if a != nil || !errors.Is(err, unix.EBUSY) || !reflect.DeepEqual(m.events, want) || m.record.Phase != liveSealSealing {
		t.Fatalf("authority=%v err=%v events=%v record=%v", a, err, m.events, m.record)
	}
	m = newLiveSealModel(t)
	m.removeErr = unix.EBUSY
	m.advance["remove"] = liveSealBudget
	a, err = m.barrier().seal()
	if a != nil || !errors.Is(err, unix.EBUSY) || m.events[len(m.events)-1] != "remove" {
		t.Fatalf("budget renewed: %v %v", err, m.events)
	}
}
func TestLiveCgroupSealMissingCgroupIsNotSuccess(t *testing.T) {
	m := newLiveSealModel(t)
	m.removeErr = unix.ENOENT
	a, err := m.barrier().seal()
	if a != nil || !errors.Is(err, unix.ENOENT) || m.record.Phase != liveSealSealing || m.events[len(m.events)-1] != "remove" {
		t.Fatalf("authority=%v err=%v events=%v record=%v", a, err, m.events, m.record)
	}
}
func TestLiveCgroupSealSingleOverallBudget(t *testing.T) {
	for _, stage := range []string{"kill", "drain", "reservation", "legacy", "read-seal", "pending", "identity", "remove", "sealed"} {
		t.Run(stage, func(t *testing.T) {
			m := newLiveSealModel(t)
			m.advance[stage] = liveSealBudget
			a, err := m.barrier().seal()
			if a != nil || err == nil || m.events[len(m.events)-1] != stage {
				t.Fatalf("authority=%v err=%v events=%v", a, err, m.events)
			}
		})
	}
}
func TestLiveCgroupSealRejectsUnknownAndChangedBinding(t *testing.T) {
	for _, mutation := range []func(*liveSealModel){
		func(m *liveSealModel) { m.reservation.Network = &networkJournal{} },
		func(m *liveSealModel) { m.reservation.Version = 1 },
		func(m *liveSealModel) { m.reservation.Binding.Generation++ },
		func(m *liveSealModel) { m.legacy.Network = &networkJournal{} },
		func(m *liveSealModel) { m.record.Phase = liveSealSealing },
		func(m *liveSealModel) { m.record.Phase = "unknown" },
		func(m *liveSealModel) { m.record.Binding.AnchorIno++ },
	} {
		m := newLiveSealModel(t)
		mutation(m)
		a, err := m.barrier().seal()
		if a != nil || err == nil || m.events[0] != "kill" {
			t.Fatalf("authority=%v err=%v events=%v", a, err, m.events)
		}
		for _, e := range m.events {
			if e == "remove" || e == "pending" {
				t.Fatalf("bad record authorized mutation: %v", m.events)
			}
		}
	}
}
func TestLiveSealDurableFilesAndStrictSchema(t *testing.T) {
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	base := int(dir.Fd())
	owner := uint32(os.Geteuid())
	b := testLiveSealBinding()
	slot := &launchSlot{UID: b.UID, Index: b.Index}
	r := liveReservation{Version: 2, Kind: "live-reservation", Binding: b}
	if err := writeJournal(base, slot, testLegacyForBinding(b), true); err != nil {
		t.Fatal(err)
	}
	if err := writeLiveRecord(base, liveReservationName(slot), r, true, owner); err != nil {
		t.Fatal(err)
	}
	s := liveSealRecord{2, "live-cgroup-seal", b, liveSealOpen}
	if err := writeLiveRecord(base, liveSealName(slot), s, true, owner); err != nil {
		t.Fatal(err)
	}
	s.Phase = liveSealSealing
	if err := writeLiveRecord(base, liveSealName(slot), s, false, owner); err != nil {
		t.Fatal(err)
	}
	// A separate late layout write cannot overwrite the seal sibling.
	layout := slotName(slot.UID, slot.Index) + ".live-layout"
	if err := writeLiveRecord(base, layout, struct {
		Phase string `json:"phase"`
	}{"late"}, true, owner); err != nil {
		t.Fatal(err)
	}
	got, ok, err := readLiveSeal(base, slot, owner)
	if err != nil || !ok || got != s {
		t.Fatalf("seal=%+v exists=%t err=%v", got, ok, err)
	}
	if authority, err := readRecordedLiveCgroupSeal(base, slot, b, owner); err == nil || authority != nil {
		t.Fatal("pending sealing authorized recovery, even with absent cgroup")
	}
	if err := rejectLiveSlotMarkers(base, slot); err == nil {
		t.Fatal("legacy cleanup accepted live marker")
	}
	path := filepath.Join(dir.Name(), liveSealName(slot))
	original, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		"unknown-field":   strings.TrimSuffix(string(original), "}") + `,"extra":1}`,
		"duplicate-field": strings.TrimSuffix(string(original), "}") + `,"phase":"cgroup-sealing"}`,
		"unknown-phase":   strings.Replace(string(original), "cgroup-sealing", "unknown", 1),
		"noncanonical":    string(original) + "\n",
		"partial":         string(original[:len(original)-1]),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, err := readLiveSeal(base, slot, owner)
			if err == nil {
				t.Fatal("invalid record accepted")
			}
		})
	}
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".pending", []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readLiveSeal(base, slot, owner); err == nil {
		t.Fatal("pending write accepted")
	}
	if err := os.Remove(path + ".pending"); err != nil {
		t.Fatal(err)
	}
	s.Phase = liveSealRecorded
	if err := writeLiveRecord(base, liveSealName(slot), s, false, owner); err != nil {
		t.Fatal(err)
	}
	got, ok, err = readLiveSeal(base, slot, owner)
	if err != nil || !ok || got != s {
		t.Fatalf("recorded seal=%+v exists=%t err=%v", got, ok, err)
	}
	for _, name := range []string{journalName(slot), layout, liveReservationName(slot), liveSealName(slot)} {
		if _, err := os.Stat(filepath.Join(dir.Name(), name)); err != nil {
			t.Fatalf("barrier removed %s: %v", name, err)
		}
	}
	if authority, err := readRecordedLiveCgroupSeal(base, slot, b, owner); err != nil || authority == nil {
		t.Fatalf("sealed recovery: %v", err)
	}
	changed := b
	changed.Generation++
	if authority, err := readRecordedLiveCgroupSeal(base, slot, changed, owner); err == nil || authority != nil {
		t.Fatal("changed binding accepted")
	}
	j := testLegacyForBinding(b)
	j.Network = &networkJournal{}
	badNetwork, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir.Name(), journalName(slot)), badNetwork, 0o600); err != nil {
		t.Fatal(err)
	}
	if authority, err := readRecordedLiveCgroupSeal(base, slot, b, owner); err == nil || authority != nil {
		t.Fatal("network-bearing recovery accepted")
	}
}
func TestLiveReservationCannotUpgradeLegacyOrNetwork(t *testing.T) {
	b := testLiveSealBinding()
	slot := &launchSlot{UID: b.UID, Index: b.Index}
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	legacy := slotJournal{Version: 1, UID: b.UID, Index: b.Index, Nonce: b.Nonce, ParentPID: b.ParentPID, ParentIdentity: b.ParentIdentity, Phase: "ready", AnchorIno: b.AnchorIno, CgroupIno: b.CgroupIno}
	data, _ := json.Marshal(legacy)
	if err := os.WriteFile(filepath.Join(dir.Name(), liveReservationName(slot)), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readLiveReservation(int(dir.Fd()), slot, uint32(os.Geteuid())); err == nil {
		t.Fatal("v1 upgraded")
	}
	if err := validateLiveReservation(slot, liveReservation{Version: 2, Kind: "live-reservation", Binding: b, Network: &networkJournal{}}); err == nil {
		t.Fatal("network accepted")
	}
}
