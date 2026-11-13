package policy

import (
	"slices"
	"strings"
	"testing"
)

func TestOverlayGuardsReserveThenExempt(t *testing.T) {
	target := "/project/pkg/node_modules"
	guards, err := OverlayGuards([]string{"node_modules"}, []string{target}, []string{"/project/***"})
	if err != nil {
		t.Fatal(err)
	}
	deny := "deny/" + WriteCaps + "+/**/node_modules/***"
	allow := "allow/" + WriteCaps + "+" + target + "/***"
	if guards[0] != deny || slices.Index(guards, allow) <= 0 {
		t.Fatalf("wrong guard order: %v", guards)
	}
	for _, p := range []string{target, "/project/pkg", "/project"} {
		if !slices.Contains(guards, "deny/rename,delete,rmdir,symlink+"+p) {
			t.Fatalf("missing ancestor lock %s", p)
		}
	}
	revoked, err := OverlayGuards([]string{"node_modules"}, []string{target}, nil)
	if err != nil || slices.Contains(revoked, allow) || revoked[0] != deny {
		t.Fatalf("revocation left exemption: %v %v", revoked, err)
	}
	if OverlayWritable(target, []string{target}) || OverlayWritable(target, []string{"/project/*"}) {
		t.Fatal("narrow grant widened to subtree")
	}
	for _, name := range []string{"*", "../target", "a\nb", "a/b", ".git"} {
		if ValidOverlayName(name) {
			t.Fatalf("unsafe name %q", name)
		}
	}
	if got := OverlayTarget([]string{"node_modules"}, target+"/nested/file"); got != target {
		t.Fatalf("target=%s", got)
	}
}

func TestProfileIncludesDenyFirstGuardsAfterOrdinaryGrants(t *testing.T) {
	profile, err := CompileProfile(ProfileInput{Project: "/project", IPC: "@test", OverlayNames: []string{"node_modules"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(profile, "sandbox/stat:on") {
		t.Fatal("O_PATH/stat guard missing")
	}
	if strings.Index(profile, "deny/"+WriteCaps+"+/**/node_modules/***") < strings.Index(profile, "allow/"+WriteCaps+"+/project/***") {
		t.Fatal("ordinary grants override guard")
	}
}
