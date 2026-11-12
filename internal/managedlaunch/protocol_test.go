package managedlaunch

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Gobd/syd-guard/internal/config"
)

func TestDecodeRequest(t *testing.T) {
	id := strings.Repeat("a", 64)
	request := Request{Credential: id, ProjectID: id, Name: "default", Revision: id, Engine: FixedEnginePath, Home: "/home/user", ConfigHome: "/home/user/.config", Args: []string{"/bin/echo", "ok"}}
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRequest(strings.NewReader(string(data))); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{
		strings.Replace(string(data), `"name":"default"`, `"name":"default","name":"other"`, 1),
		strings.Replace(string(data), `"name":"default"`, `"name":null`, 1),
		strings.Replace(string(data), `"name":"default"`, `"extra":1`, 1),
		string(data) + `{}`,
		strings.Replace(string(data), `,"require_pie":false`, "", 1),
		strings.Replace(strings.Replace(string(data), `,"require_pie":false`, "", 1), `"name":"default"`, `"name":"default","NAME":"default"`, 1),
		strings.Replace(string(data), `"require_pie":false`, `"Require_Pie":false`, 1),
		strings.Repeat("x", Limit+1),
		strings.Replace(string(data), "default", string([]byte{0xff}), 1),
	} {
		if _, err := DecodeRequest(strings.NewReader(input)); err == nil {
			t.Fatal("accepted malformed request")
		}
	}
	request.Args = nil
	if request.Validate() == nil {
		t.Fatal("accepted empty argv")
	}
	request.Args = []string{string([]byte{0xff})}
	if request.Validate() == nil {
		t.Fatal("accepted invalid UTF-8 argv")
	}
	request.Args = []string{"echo"}
	request.Engine = "syd"
	if request.Validate() == nil {
		t.Fatal("accepted relative engine")
	}
}

func TestReadOnlyProfileRejectsUnsupportedIntent(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		profile config.Profile
		valid   bool
	}{
		{"relative read", config.Profile{Version: 1, Name: "default", Files: []config.FileRule{{Path: "file", Access: []string{"read"}}}, Network: []config.NetworkRule{}}, true},
		{"project read", config.Profile{Version: 1, Name: "default", Files: []config.FileRule{{Path: ".", Access: []string{"read"}, Recursive: true}}, Network: []config.NetworkRule{}}, true},
		{"write", config.Profile{Version: 1, Name: "default", Files: []config.FileRule{{Path: "file", Access: []string{"write"}}}, Network: []config.NetworkRule{}}, false},
		{"absolute", config.Profile{Version: 1, Name: "default", Files: []config.FileRule{{Path: "/etc/passwd", Access: []string{"read"}}}, Network: []config.NetworkRule{}}, false},
		{"home", config.Profile{Version: 1, Name: "default", Files: []config.FileRule{{Path: "~/data", Access: []string{"read"}}}, Network: []config.NetworkRule{}}, false},
		{"network", config.Profile{Version: 1, Name: "default", Files: []config.FileRule{}, Network: []config.NetworkRule{{Host: "example.com", Port: 443, Transport: "tcp"}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.profile)
			if err != nil {
				t.Fatal(err)
			}
			snap, err := config.ParseManagedProfileSnapshot("default", data)
			if err != nil {
				t.Fatal(err)
			}
			_, err = ReadOnlyProfile(snap, root)
			if (err == nil) != tc.valid {
				t.Fatalf("subset acceptance: %v", err)
			}
		})
	}
	if err := os.Symlink("/etc", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"version":1,"name":"default","files":[{"path":"link/passwd","access":["read"],"recursive":false}],"network":[]}`)
	snap, err := config.ParseManagedProfileSnapshot("default", data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadOnlyProfile(snap, root); err == nil {
		t.Fatal("symlink escaped project")
	}
}
