package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestHelpAndVersion(t *testing.T) {
	for _, args := range [][]string{nil, {"help"}, {"version"}} {
		var out, err bytes.Buffer
		if code := run(args, &out, &err); code != 0 || out.Len() == 0 {
			t.Fatalf("%v: code=%d out=%s err=%s", args, code, &out, &err)
		}
	}
}

func TestUnvalidatedLaunchesFailClosed(t *testing.T) {
	var out, err bytes.Buffer
	if code := run([]string{"run", "--", "anything"}, &out, &err); code != 2 || !strings.Contains(err.String(), "no unconfined fallback") {
		t.Fatalf("run: code=%d error=%s", code, &err)
	}
	out.Reset()
	err.Reset()
	if code := run([]string{"learn", "--", "anything"}, &out, &err); code == 0 || !strings.Contains(err.String(), "discovery recording is not yet available") {
		t.Fatalf("learn: code=%d error=%s", code, &err)
	}
}

func TestInvalidBackendNeverLaunchesVM(t *testing.T) {
	var out, err bytes.Buffer
	if code := run([]string{"doctor", "--backend", "invalid"}, &out, &err); code != 2 || !strings.Contains(err.String(), "unknown backend") {
		t.Fatalf("code=%d error=%s", code, &err)
	}
}
