package managedstore

import (
	"encoding/json"
	"testing"
)

func TestStrictRequest(t *testing.T) {
	valid := `{"operation":"read","project":"id","name":"test","credential":"token"}`
	if _, err := decodeRequest([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		`{"operation":"read","operation":"create","project":"id","name":"test","credential":"token"}`,
		`{"operation":"read","project":"id","name":"test","credential":"a","credential":"b"}`,
		`{"Operation":"read","project":"id","name":"test","credential":"token"}`,
		`{"operation":"read","project":"id","name":"test","credential":null}`,
		`{"operation":null,"project":"id","name":"test","credential":"token"}`,
		`{"operation":"read","project":null,"name":"test","credential":"token"}`,
		`{"operation":"read","project":"id","name":null,"credential":"token"}`,
		`{"operation":"replace","project":"id","name":"test","credential":"token","expected_revision":null,"profile":"e30="}`,
		`{"operation":"replace","project":"id","name":"test","credential":"token","expected_revision":"x","profile":null}`,
		`{"operation":"replace","project":"id","name":"test","credential":"token","expected_revision":"x","profile":"e30=","profile":"e30="}`,
		`{"operation":"read","project":"id","name":"test","credential":"token","profile":""}`,
		`{"operation":"read","project":"id","name":"test","credential":"token","expected_revision":""}`,
		`{"operation":"read","project":"id","name":"test","credential":"token","extra":1}`,
		valid + ` {}`, string(append([]byte(valid[:len(valid)-2]), 0xff, '"', '}')),
	} {
		if _, err := decodeRequest([]byte(value)); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
	for _, r := range []Request{{Operation: "register", Project: "/tmp/x", Credential: "c"}, {Operation: "read", Project: "id", Name: "test", Credential: "c"}, {Operation: "replace", Project: "id", Name: "test", Expected: "rev", Profile: []byte("{}"), Credential: "c"}} {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeRequest(b); err != nil {
			t.Fatalf("marshal %s: %v", b, err)
		}
	}
}

func TestStrictResponse(t *testing.T) {
	for _, value := range []string{
		`{"revision":"x","revision":"y","profile":"e30="}`,
		`{"Revision":"x","profile":"e30="}`,
		`{"revision":null,"profile":"e30="}`,
		`{"revision":"x","profile":null}`,
		`{"revision":"x","profile":"e30=","profile":"e30="}`,
		`{"error":"x","code":null}`,
		`{"error":"x","error":"y","code":"error"}`,
		`{"error":"x","Code":"error"}`,
		`{"revision":"x","profile":"e30=","error":""}`,
		`{"error":"x"}`,
		`{"revision":"x","profile":"e30="} {}`,
		string([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}),
	} {
		if _, err := decodeResponse([]byte(value), "read"); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
	if _, err := decodeResponse([]byte(`{"revision":"x","profile":"e30="}`), "read"); err != nil {
		t.Fatal(err)
	}
}
