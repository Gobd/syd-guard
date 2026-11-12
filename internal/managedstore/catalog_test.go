//go:build linux || darwin

package managedstore

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestCatalogWireAndClientValidation(t *testing.T) {
	id := strings.Repeat("a", 64)
	entry := CatalogEntry{Project: id, Name: "default", Revision: strings.Repeat("b", 64), Namespace: &ProjectNamespace{Path: "/project", ProjectDev: 1, ProjectIno: 2, PolicyDev: 1, PolicyIno: 3}}
	entries := []CatalogEntry{entry}
	encode := func(entries []CatalogEntry) []byte {
		t.Helper()
		b, err := json.Marshal(Response{Catalog: &entries})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, data := range [][]byte{[]byte(`{"catalog":[]}`), encode(entries)} {
		if _, err := processHelperResponse(Request{Operation: "catalog"}, boundedBuffer{data: data}, nil, false); err != nil {
			t.Fatalf("valid catalog: %v", err)
		}
	}
	valid := string(encode(entries))
	bad := []string{
		`{"catalog":null}`, `{"catalog":{}}`, `{"catalog":[null]}`, `{"catalog":[],"catalog":[]}`,
		`{"Catalog":[]}`, `{"catalog":[],"project":"leak"}`, `{"catalog":[]} {}`,
		strings.Replace(valid, `"name":"default"`, `"Name":"default"`, 1),
		strings.Replace(valid, `"name":"default"`, `"name":null`, 1),
		strings.Replace(valid, `"name":"default"`, `"name":"default","name":"default"`, 1),
		strings.Replace(valid, `"path":"/project"`, `"Path":"/project"`, 1),
		strings.Replace(valid, `"path":"/project"`, `"path":null`, 1),
		strings.Replace(valid, `"path":"/project"`, `"path":"/project","path":"/other"`, 1),
		strings.Replace(valid, `"project_dev":1`, `"project_dev":1,"unknown":1`, 1),
		strings.Repeat(" ", 2*Limit+8193),
	}
	for _, data := range bad {
		if _, err := decodeResponse([]byte(data), "catalog"); err == nil {
			t.Fatalf("accepted invalid wire: %.150s", data)
		}
	}
	badEntries := [][]CatalogEntry{}
	for _, change := range []func(*CatalogEntry){
		func(e *CatalogEntry) { e.Project = strings.Repeat("A", 64) },
		func(e *CatalogEntry) { e.Name = "../bad" },
		func(e *CatalogEntry) { e.Revision = strings.Repeat("G", 64) },
		func(e *CatalogEntry) { e.Namespace = nil },
		func(e *CatalogEntry) { e.Namespace = &ProjectNamespace{Path: "relative", ProjectIno: 2, PolicyIno: 3} },
		func(e *CatalogEntry) { e.Namespace = &ProjectNamespace{Path: "/project", PolicyIno: 3} },
		func(e *CatalogEntry) {
			e.Namespace = &ProjectNamespace{Path: "/", ProjectDev: 1, ProjectIno: 2, PolicyDev: 1, PolicyIno: 3}
		},
		func(e *CatalogEntry) {
			e.Namespace = &ProjectNamespace{Path: "/project", ProjectDev: 1, ProjectIno: 2, PolicyDev: 2, PolicyIno: 3}
		},
	} {
		e := entry
		change(&e)
		badEntries = append(badEntries, []CatalogEntry{e})
	}
	badEntries = append(badEntries, []CatalogEntry{entry, entry}, make([]CatalogEntry, maxCatalogProfiles+1))
	other := entry
	other.Name = "other"
	other.Namespace = &ProjectNamespace{Path: "/other", ProjectIno: 5, PolicyIno: 6}
	badEntries = append(badEntries, []CatalogEntry{entry, other})
	other.Project = strings.Repeat("c", 64)
	other.Namespace = entry.Namespace
	badEntries = append(badEntries, []CatalogEntry{entry, other})
	for _, v := range badEntries {
		if _, err := processHelperResponse(Request{Operation: "catalog"}, boundedBuffer{data: encode(v)}, nil, false); err == nil || errors.Is(err, ErrIndeterminate) {
			t.Fatalf("accepted invalid catalog or indeterminate: %v", err)
		}
	}
	response, err := validateResponse(Request{Operation: "catalog"}, Response{Catalog: &entries})
	if err != nil {
		t.Fatal(err)
	}
	entries[0].Namespace.Path = "/mutated"
	if (*response.Catalog)[0].Namespace.Path != "/project" {
		t.Fatal("catalog namespace not defensively owned")
	}
	for _, b := range []boundedBuffer{{overflow: true}, {data: []byte(`{"error":"uncertain","code":"indeterminate"}`)}, {data: []byte("bad")}} {
		if _, err := processHelperResponse(Request{Operation: "catalog"}, b, errors.New("transport"), false); err == nil || errors.Is(err, ErrIndeterminate) {
			t.Fatalf("catalog transport error: %v", err)
		}
	}
	if _, err := processHelperResponse(Request{Operation: "catalog"}, boundedBuffer{}, nil, true); err == nil || errors.Is(err, ErrIndeterminate) {
		t.Fatalf("catalog deadline: %v", err)
	}
}

func TestCatalogRequestShape(t *testing.T) {
	for _, data := range []string{`{"operation":"catalog","credential":"token"}`, `{"operation":"catalog","credential":"token","project":""}`, `{"operation":"catalog","credential":"token","name":"x"}`, `{"operation":"catalog","credential":"token","root":"/tmp"}`} {
		_, err := decodeRequest([]byte(data))
		if strings.Count(data, ",") == 1 && err != nil {
			t.Fatal(err)
		}
		if strings.Count(data, ",") != 1 && err == nil {
			t.Fatalf("accepted %s", data)
		}
	}
	b, err := json.Marshal(Request{Operation: "catalog", Credential: "token"})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"operation":"catalog","credential":"token"}` {
		t.Fatal(string(b))
	}
}
