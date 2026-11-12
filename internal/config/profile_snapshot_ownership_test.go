package config

import (
	"bytes"
	"testing"
)

func TestManagedProfileSnapshotOwnsSlicedHelperBytes(t *testing.T) {
	data := []byte(`{"version":1,"name":"build","files":[{"path":"src","access":["read"],"recursive":false}],"network":[]}`)
	buffer := append([]byte("prefix"), data...)
	buffer = append(buffer, []byte("suffix")...)
	input := buffer[len("prefix") : len("prefix")+len(data)]
	snapshot, err := ParseManagedProfileSnapshot("build", input)
	if err != nil {
		t.Fatal(err)
	}
	before, revision := snapshot.Bytes(), snapshot.Revision()
	for i := range buffer {
		buffer[i] = 'x'
	}
	if !bytes.Equal(snapshot.Bytes(), before) || snapshot.Revision() != revision {
		t.Fatal("snapshot aliases helper input")
	}
	profile := snapshot.Profile()
	profile.Files[0].Access[0] = "write"
	returned := snapshot.Bytes()
	returned[0] = 'x'
	if !bytes.Equal(snapshot.Bytes(), before) || snapshot.Profile().Files[0].Access[0] != "read" {
		t.Fatal("snapshot exposed mutable data")
	}
}
