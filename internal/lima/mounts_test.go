package lima

import "testing"

func TestMapDirectoryUsesLongestComponentBoundary(t *testing.T) {
	mounts := []Mount{{Location: "/Users/briankemper/Developer", MountPoint: "/workspace"}, {Location: "/Users/briankemper/Developer/nested", MountPoint: "/nested"}}
	for _, tc := range []struct{ source, want string }{{"/Users/briankemper/Developer/syd-guard", "/workspace/syd-guard"}, {"/Users/briankemper/Developer/nested/repo", "/nested/repo"}} {
		got, err := MapDirectory(tc.source, mounts)
		if err != nil || got != tc.want {
			t.Fatalf("%s: %s %v", tc.source, got, err)
		}
	}
	if _, err := MapDirectory("/Users/briankemper/Developer-other/repo", mounts); err == nil {
		t.Fatal("accepted sibling prefix")
	}
}

func TestGuestCommandValidatesExplicitPaths(t *testing.T) {
	for _, p := range []string{"relative", "/", "/tmp/../bad", "/tmp/a\nb"} {
		if _, err := GuestCommand(p, "", nil); err == nil {
			t.Fatalf("accepted %q", p)
		}
	}
	cmd, err := GuestCommand("/tmp/candidate", "/home/user/private", []string{"operator-api"})
	if err != nil || len(cmd) != 4 || cmd[0] != "/usr/bin/env" || cmd[1] != "XDG_CONFIG_HOME=/home/user/private" || cmd[2] != "/tmp/candidate" {
		t.Fatalf("%v %v", cmd, err)
	}
}
