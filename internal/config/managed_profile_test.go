package config

import "testing"

func TestParseManagedProfileSnapshot(t *testing.T) {
	valid := []string{
		`{"version":1,"name":"build","files":[],"network":[]}`,
		`{"version":1,"name":"build","files":[{"path":"src","capabilities":["read"],"recursive":false}],"network":[{"host":"example.com","port":443,"transport":"tcp"}]}`,
	}
	for _, data := range valid {
		if _, err := ParseManagedProfileSnapshot("build", []byte(data)); err != nil {
			t.Fatalf("valid profile %s: %v", data, err)
		}
	}
	invalid := []string{
		`{"version":1,"name":"build"}`,
		`{"version":1,"name":"build","files":null,"network":[]}`,
		`{"version":1,"name":"build","files":[],"network":null}`,
		`{"version":1,"name":"build","files":[{"path":"src","capabilities":["read"]}],"network":[]}`,
		`{"version":1,"name":"build","files":[{"path":"src","capabilities":["read"],"recursive":null}],"network":[]}`,
		`{"version":1,"name":"build","files":[{"path":"src","capabilities":["read"],"recursive":false,"extra":1}],"network":[]}`,
		`{"version":1,"name":"build","files":[],"network":[{"host":"example.com","port":443}]}`,
		`{"version":1,"name":"build","files":[],"network":[],"files":[]}`,
	}
	for _, data := range invalid {
		if _, err := ParseManagedProfileSnapshot("build", []byte(data)); err == nil {
			t.Errorf("accepted invalid profile %s", data)
		}
	}
}
