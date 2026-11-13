package policy

import (
	"strings"
	"testing"
)

func TestOverlayRoot(t *testing.T) {
	names := []string{"node_modules", ".venv"}
	for path, want := range map[string]string{
		"/p/node_modules":                    "/p/node_modules",
		"/p/web/node_modules/x/node_modules": "/p/web/node_modules",
		"/p/.venv/bin/python":                "/p/.venv",
		"/p/src/main.go":                     "",
		"/p":                                 "",
		"/q/sibling/node_modules/x":          "/q/sibling/node_modules",
		"/other/node_modules/x":              "",
		"/pp/node_modules":                   "",
	} {
		if got := OverlayRoot([]string{"/p", "/q"}, names, path); got != want {
			t.Errorf("OverlayRoot(%s) = %q, want %q", path, got, want)
		}
	}
}

// The guard must come after ordinary grants (Syd: last match wins), mounted
// folders must be re-allowed after it, and protected denies must stay last.
func TestProfileOverlayGuardOrder(t *testing.T) {
	prof, err := CompileProfile(ProfileInput{
		Project: "/p", IPC: "@t", OverlayNames: []string{"node_modules"}, OverlayRoots: []string{"/p"},
		Overlays: []Overlay{{Source: "/cache/web/node_modules", Target: "/p/web/node_modules"}},
		Protect:  ProtectedFor("/p"),
	})
	if err != nil {
		t.Fatal(err)
	}
	grant := strings.Index(prof, "allow/"+WriteCaps+"+/p/***")
	deny := strings.Index(prof, "deny/"+ModifyCaps+"+/p/**/node_modules/***")
	mounted := strings.Index(prof, "allow/"+ModifyCaps+"+/p/web/node_modules/***")
	protect := strings.Index(prof, "deny/"+ModifyCaps+"+/p/.git/hooks")
	if grant < 0 || deny < grant || mounted < deny || protect < mounted {
		t.Fatalf("bad order: grant=%d deny=%d mounted=%d protect=%d\n%s", grant, deny, mounted, protect, prof)
	}
	if strings.Contains(prof, "deny/"+WriteCaps+"+/p/**/node_modules") {
		t.Fatal("guard must not block reads of an existing host copy")
	}
	if p, _ := CompileProfile(ProfileInput{Project: "/p", IPC: "@t"}); strings.Contains(p, "node_modules") {
		t.Fatal("no keepOnVM names: no guard")
	}
}
