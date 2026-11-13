package managedlive

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func id(c string) string { return strings.Repeat(c, 64) }
func testBinding() Binding {
	return Binding{Session: id("a"), Project: id("b"), Profile: "build", Generation: 1}
}
func testUpdate(pred BankReceipt) *ApplySaved {
	return &ApplySaved{Version: Version, Kind: "apply_saved", Credential: id("c"), Binding: pred.Binding, RequestID: id("d"), Sequence: pred.Sequence + 1, Revision: id("e"), Predecessor: pred}
}
func TestProtocolExactFrames(t *testing.T) {
	m := testUpdate(BankReceipt{Binding: testBinding()})
	b, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Decode(b); err != nil {
		t.Fatal(err)
	}
	cases := []string{
		strings.Replace(string(b), `"version":2`, `"version":2,"version":2`, 1),
		strings.Replace(string(b), `"session":`, `"extra":1,"session":`, 1),
		strings.Replace(string(b), `"generation":1`, `"generation":null`, 1),
		strings.Replace(string(b), `"generation":1`, `"generation":1,"generation":1`, 1),
		strings.Replace(string(b), `"sequence":1,`, ``, 1),
		string(b) + ` {}`,
		strings.Replace(string(b), `"apply_saved"`, `"raw_command"`, 1),
	}
	for _, input := range cases {
		if _, err = Decode([]byte(input)); err == nil {
			t.Errorf("accepted %s", input)
		}
	}
	var buf bytes.Buffer
	if err = WriteFrame(&buf, m); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&buf)
	if err != nil || *got.(*ApplySaved) != *m {
		t.Fatalf("roundtrip %v %v", got, err)
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], MaxFrame+1)
	if _, err = ReadFrame(bytes.NewReader(h[:])); err == nil {
		t.Fatal("oversize accepted")
	}
}
func TestStateReceiptsDeadlinesAndReplay(t *testing.T) {
	now := time.Unix(100, 0)
	b := testBinding()
	s, err := NewState(b, id("1"), id("2"), id("3"), now)
	if err != nil {
		t.Fatal(err)
	}
	initial := BankReceipt{Binding: b, Sequence: 1, Revision: id("3")}
	ready, err := s.CompleteInitial(id("2"), initial, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	_, _, deadline := s.Snapshot()
	if deadline != now.Add(StartupTimeout) {
		t.Fatal("initial ACK renewed deadline")
	}
	wrong := ready.Receipt
	wrong.Bank.Sequence++
	if s.Release(wrong, now) == nil {
		t.Fatal("wrong release accepted")
	}
	if err = s.Release(ready.Receipt, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if s.Release(ready.Receipt, now) == nil {
		t.Fatal("duplicate release accepted")
	}
	m := testUpdate(initial)
	deadline, err = s.AcceptUpdate(*m, now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if deadline != now.Add(3*time.Second+UpdateTimeout) {
		t.Fatal(deadline)
	}
	if _, err = s.AcceptUpdate(*m, now); err == nil {
		t.Fatal("busy accepted")
	}
	status, err := s.Status()
	if err != nil || status.Receipt != ready.Receipt {
		t.Fatal("pending update changed status receipt", err)
	}
	_, _, observed := s.Snapshot()
	if observed != deadline {
		t.Fatal("status renewed deadline")
	}
	applied := BankReceipt{Binding: b, Sequence: 2, Revision: m.Revision}
	result, err := s.CompleteUpdate(m.RequestID, applied, true, now.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	status, err = s.Status()
	if err != nil || status.Receipt != result.Receipt {
		t.Fatal("status did not retain exact applied receipt", err)
	}
	// An ABA revision cannot make an old predecessor or reused request valid.
	replay := testUpdate(applied)
	replay.RequestID = m.RequestID
	replay.Revision = initial.Revision
	if _, err = s.AcceptUpdate(*replay, now); err == nil {
		t.Fatal("replayed request accepted")
	}
	replay.RequestID = id("f")
	replay.Predecessor = initial
	replay.Sequence = 2
	if _, err = s.AcceptUpdate(*replay, now); err == nil {
		t.Fatal("stale predecessor accepted")
	}
}
func TestStateAcceptedOperationCeilingPreservesHistory(t *testing.T) {
	now := time.Unix(100, 0)
	b := testBinding()
	s, err := NewState(b, id("1"), id("2"), id("3"), now)
	if err != nil {
		t.Fatal(err)
	}
	current := BankReceipt{Binding: b, Sequence: 1, Revision: id("3")}
	ready, err := s.CompleteInitial(id("2"), current, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Release(ready.Receipt, now); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < MaxAcceptedOperations; i++ {
		m := testUpdate(current)
		m.RequestID = fmt.Sprintf("%064x", i)
		if i%2 == 0 {
			m.Revision = id("3")
		} // ABA revisions do not reset history.
		if _, err := s.AcceptUpdate(*m, now); err != nil {
			t.Fatalf("accept %d: %v", i, err)
		}
		if i == MaxAcceptedOperations-1 {
			beforePending, beforeDeadline, beforeCurrent := *s.pending, s.deadline, s.current
			history := make(map[string]bool, len(s.used))
			for k, v := range s.used {
				history[k] = v
			}
			next := testUpdate(current)
			next.RequestID = fmt.Sprintf("%064x", i+1)
			if _, err := s.AcceptUpdate(*next, now); err == nil {
				t.Fatal("accepted at limit while pending")
			}
			if *s.pending != beforePending || s.deadline != beforeDeadline || s.current != beforeCurrent || !reflect.DeepEqual(s.used, history) {
				t.Fatal("rejection changed pending state")
			}
		}
		current = BankReceipt{Binding: b, Sequence: m.Sequence, Revision: m.Revision}
		if _, err := s.CompleteUpdate(m.RequestID, current, true, now); err != nil {
			t.Fatalf("complete %d: %v", i, err)
		}
	}
	if len(s.used) != MaxAcceptedOperations || !s.used[id("2")] || !s.used[fmt.Sprintf("%064x", 1)] {
		t.Fatal("accepted IDs not retained")
	}
	beforeCurrent, beforeDeadline, beforePhase, beforeLatest := s.current, s.deadline, s.phase, s.latest
	history := make(map[string]bool, len(s.used))
	for k, v := range s.used {
		history[k] = v
	}
	for _, requestID := range []string{fmt.Sprintf("%064x", MaxAcceptedOperations), id("2"), fmt.Sprintf("%064x", 1)} {
		m := testUpdate(current)
		m.RequestID = requestID
		m.Revision = id("3")
		if _, err := s.AcceptUpdate(*m, now); err == nil {
			t.Fatal("accepted beyond ceiling or reused ID")
		}
		if s.current != beforeCurrent || s.deadline != beforeDeadline || s.phase != beforePhase || s.latest != beforeLatest || s.pending != nil || !reflect.DeepEqual(s.used, history) {
			t.Fatal("rejection changed state")
		}
	}
}

func TestEncodeRejectsTypedNil(t *testing.T) {
	values := []any{nil, (*Ticket)(nil), (*Release)(nil), (*ApplySaved)(nil), (*StatusRequest)(nil), (*Ready)(nil), (*Applied)(nil), (*Status)(nil), (*Stopped)(nil), (*StartupStopped)(nil)}
	for _, v := range values {
		if _, err := Encode(v); err == nil {
			t.Errorf("Encode(%T) accepted nil", v)
		}
		var b bytes.Buffer
		if err := WriteFrame(&b, v); err == nil || b.Len() != 0 {
			t.Errorf("WriteFrame(%T) accepted nil or wrote bytes", v)
		}
	}
}

func TestStateFailsStopOnAcceptedFailureAndTimeout(t *testing.T) {
	now := time.Unix(100, 0)
	b := testBinding()
	for _, timeout := range []bool{false, true} {
		s, _ := NewState(b, id("1"), id("2"), id("3"), now)
		initial := BankReceipt{Binding: b, Sequence: 1, Revision: id("3")}
		r, _ := s.CompleteInitial(id("2"), initial, now)
		_ = s.Release(r.Receipt, now)
		m := testUpdate(initial)
		deadline, err := s.AcceptUpdate(*m, now)
		if err != nil {
			t.Fatal(err)
		}
		when := now
		if timeout {
			when = deadline
		}
		_, err = s.CompleteUpdate(m.RequestID, BankReceipt{Binding: b, Sequence: 2, Revision: m.Revision}, timeout, when)
		if err == nil {
			t.Fatal("uncertain ACK accepted")
		}
		phase, _, _ := s.Snapshot()
		if phase != "stopped" {
			t.Fatal(phase)
		}
	}
	s, _ := NewState(b, id("1"), id("2"), id("3"), now)
	_, err := s.CompleteInitial(id("2"), BankReceipt{Binding: b, Sequence: 1, Revision: id("3")}, now.Add(StartupTimeout))
	if err == nil {
		t.Fatal("late initial accepted")
	}
}
