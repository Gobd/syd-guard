package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestSelectedRunRejectsIncompleteOrUnsupportedOptions(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		message string
	}{
		{[]string{"run", "--config", "default", "--", "true"}, "selected profiles require"},
		{[]string{"run", "--project-id", "x", "--", "true"}, "require --config"},
		{[]string{"run", "--config", "default", "--project-id", "x", "--expected-revision", "y", "--no-network", "--scope", "/tmp", "--", "true"}, "do not support"},
	} {
		var out, stderr bytes.Buffer
		if code := run(tc.args, &out, &stderr); code == 0 || !strings.Contains(stderr.String(), tc.message) {
			t.Fatalf("args %q: code=%d stderr=%s", tc.args, code, stderr.String())
		}
	}
}
