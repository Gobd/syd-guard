package syd

import (
	"reflect"
	"testing"
)

func TestExpandFileAccess(t *testing.T) {
	tests := []struct{ access, want []string }{
		{[]string{"read"}, []string{"read", "stat", "readdir", "chdir", "readlink"}},
		{[]string{"write"}, []string{"write", "create", "truncate", "chmod", "chattr", "mkdir", "symlink"}},
		{[]string{"delete"}, []string{"delete", "rmdir", "rename"}},
	}
	for _, tt := range tests {
		got, err := ExpandFileAccess(tt.access)
		if err != nil || !reflect.DeepEqual(got, tt.want) {
			t.Fatalf("%v: %v %v", tt.access, got, err)
		}
	}
	for _, value := range [][]string{nil, {"exec"}, {"read", "read"}, {"chmod"}} {
		if _, err := ExpandFileAccess(value); err == nil {
			t.Fatalf("accepted %v", value)
		}
	}
}
