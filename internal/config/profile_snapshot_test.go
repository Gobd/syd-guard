package config

import (
	"bytes"
	"strings"
	"testing"
)

func TestProfileSnapshotValidation(t *testing.T) {
	valid := `{"version":1,"name":"build","files":[{"path":"./src","access":["read","write"],"recursive":true}],"network":[{"host":"example.com","port":443,"transport":"tcp"}]}`
	s, err := ParseProfileSnapshot("build", []byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Revision()) != 64 {
		t.Fatalf("revision %q", s.Revision())
	}
	original := s.Bytes()
	original[0] = 'x'
	if bytes.Equal(original, s.Bytes()) {
		t.Fatal("snapshot exposed mutable bytes")
	}
	p := s.Profile()
	p.Files[0].Access[0] = "delete"
	if s.Profile().Files[0].Access[0] != "read" {
		t.Fatal("snapshot exposed mutable profile")
	}
	tests := []string{
		`{"version":1,"name":"build","name":"default","files":[],"network":[]}`,
		`{"version":1,"name":"build","Name":"default","files":[],"network":[]}`,
		`{"version":1,"name":"build","unknown":true,"files":[],"network":[]}`,
		`{"version":1,"name":"build","files":[{"path":"/","access":["read"],"recursive":true}],"network":[]}`,
		`{"version":1,"name":"build","files":[{"path":"/safe","access":["chmod"],"recursive":true}],"network":[]}`,
		`{"version":1,"name":"build","files":[{"path":"/safe","access":["read","read"],"recursive":true}],"network":[]}`,
		`{"version":1,"name":"build","files":[{"path":"/safe","access":["read"]}],"network":[]}`,
		`{"version":1,"name":"build","files":null,"network":[]}`,
		`{"version":1,"name":"build","files":[{"path":"*","access":["read"],"recursive":true}],"network":[]}`,
		`{"version":1,"name":"build","files":[{"path":"/safe","access":["ALL"],"recursive":false}],"network":[]}`,
		`{"version":1,"name":"build","files":[{"path":"~other/file","access":["read"],"recursive":false}],"network":[]}`,
		`{"version":1,"name":"build","files":[],"network":[{"host":"https://example.com","port":443,"transport":"tcp"}]}`,
		`{"version":1,"name":"build","files":[],"network":[{"host":"127.0.0.1","port":443,"transport":"tcp"}]}`,
		`{"version":1,"name":"build","files":[],"network":[{"host":"example.com","port":443,"transport":"icmp"}]}`,
		`{"version":1,"name":"build","files":[],"network":[]} {}`,
	}
	for _, v := range tests {
		if _, err := ParseProfileSnapshot("build", []byte(v)); err == nil {
			t.Errorf("accepted %s", v)
		}
	}
	if _, err := ParseProfileSnapshot("build", []byte(`{"version":1,"name":"build","files":[{"path":"src","capabilities":["read"],"recursive":false}],"network":[]}`)); err == nil || !strings.Contains(err.Error(), "migrate") {
		t.Fatalf("legacy migration error: %v", err)
	}
	if _, err := ParseProfileSnapshot("build", []byte(strings.Repeat(" ", maxProfileBytes+1))); err == nil {
		t.Error("accepted oversized document")
	}
	if _, err := ParseProfileSnapshot("build", []byte("{\"version\":1,\"name\":\"build\",\"files\":[],\"network\":[],\"x\":\"\xff\"}")); err == nil {
		t.Error("accepted invalid UTF-8")
	}
	if _, err := ParseProfileSnapshot("build", []byte(strings.Repeat("[", 66)+strings.Repeat("]", 66))); err == nil {
		t.Error("accepted excessively nested document")
	}
}

func TestMergeProfileDoesNotMutateOrPersist(t *testing.T) {
	base, err := ParseProfileSnapshot("build", []byte(`{"version":1,"name":"build","files":[],"network":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	next, err := MergeProfile(base, []FileRule{{Path: "./src", Access: []string{"read"}, Recursive: true}}, []NetworkRule{{Host: "example.com", Port: 443, Transport: "tcp"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(base.Profile().Files) != 0 || len(base.Profile().Network) != 0 || len(next.Profile().Files) != 1 || len(next.Profile().Network) != 1 || base.Revision() == next.Revision() {
		t.Fatal("merge altered base or lost intent")
	}
	if _, err := MergeProfile(base, []FileRule{{Path: "/tmp", Access: []string{"*"}}}, nil); err == nil {
		t.Fatal("merge accepted invalid capability")
	}
	if _, err := MergeProfile(ProfileSnapshot{}, nil, nil); err == nil {
		t.Fatal("merge accepted absent review")
	}
	_, err = ParseProfileSnapshot("other", next.Bytes())
	if err == nil {
		t.Fatal("wrong profile name accepted")
	}
}
