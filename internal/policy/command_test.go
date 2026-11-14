package policy

import (
	"strings"
	"testing"
)

func TestCommandExpand(t *testing.T) {
	c := Command{Run: []string{"git", "push", "-u", "origin", "{branch}"}, Args: map[string]string{"branch": "agent/[A-Za-z0-9._/-]+"}}
	argv, err := c.Expand(map[string]string{"branch": "agent/fix-1"})
	if err != nil || strings.Join(argv, " ") != "git push -u origin agent/fix-1" {
		t.Fatalf("expand: %v %v", argv, err)
	}
	for _, bad := range []map[string]string{
		{"branch": "main"},
		{"branch": "agent/x; rm -rf ~"},
		{"branch": "--force"},
		{"branch": "agent/x\nmain"},
		{},
		{"branch": "agent/x", "extra": "y"},
	} {
		if _, err := c.Expand(bad); err == nil {
			t.Errorf("Expand(%v) should fail", bad)
		}
	}
}

func TestCommandValidate(t *testing.T) {
	for _, bad := range []Command{
		{},
		{Run: []string{"{prog}"}, Args: map[string]string{"prog": ".*"}},
		{Run: []string{"gh", "{pr}"}},
		{Run: []string{"gh"}, Args: map[string]string{"unused": "x"}},
		{Run: []string{"gh", "{pr}"}, Args: map[string]string{"pr": "("}},
		{Run: []string{"gh"}, Mode: "sometimes"},
	} {
		if bad.Validate() == nil {
			t.Errorf("%+v should be invalid", bad)
		}
	}
	if ValidCommandName("Bad Name") || !ValidCommandName("pr-create") {
		t.Error("command names")
	}
}
