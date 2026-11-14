package policy

import (
	"slices"
	"strings"
	"testing"
)

func TestPathIgnoreIsAnEnforcedDeny(t *testing.T) {
	for _, mode := range []bool{false, true} {
		profile, err := CompileProfile(ProfileInput{
			Project: "/project", IPC: "@test", Learn: mode,
			Rules: []Rules{{Ignore: []string{"/project/secret/**", "telemetry.example"}}, {Write: []string{"/project/**"}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		deny := "deny/" + WriteCaps + "+/project/secret/***"
		if strings.Index(profile, deny) <= strings.LastIndex(profile, "allow/"+WriteCaps+"+/project/***") {
			t.Fatalf("ignore not enforced after grants (learn=%v): %s", mode, profile)
		}
		if strings.Contains(profile, "telemetry.example") {
			t.Fatal("host ignore reached Syd")
		}
	}
}

func TestPathIgnoreDiffAndNormalization(t *testing.T) {
	r := Rules{Ignore: []string{"/project/secret/**", "telemetry.example"}}
	deny := "deny/" + WriteCaps
	if !slices.Equal(DiffCommands(Rules{}, r), []string{deny + "+/project/secret/***"}) {
		t.Fatal("adding ignore did not enforce a path deny")
	}
	if !slices.Equal(DiffCommands(r, Rules{}), []string{deny + "-/project/secret/***"}) {
		t.Fatal("removing ignore did not revoke the path deny")
	}
	if !Ignored([]Rules{r}, "read", "/project/secret") {
		t.Fatal("directory root must match the normalized deny")
	}
	for _, path := range []string{"/project/../secret", "/project//secret", "/project\nallow/all+/***"} {
		if _, err := Normalize("ignore", path); err == nil {
			t.Fatalf("unsafe ignore accepted: %q", path)
		}
	}
}
