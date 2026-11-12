//go:build linux

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/controller"
	"github.com/Gobd/syd-guard/internal/managedlaunch"
	"github.com/Gobd/syd-guard/internal/managedstore"
)

// This verifies CLI/controller orchestration with an injected launcher, not
// mount setup, helper privilege, or an installed-helper end-to-end boundary.
func TestSelectedRunRequiresReviewAndBindsSession(t *testing.T) {
	fixture, root := managedCommandTestSetup(t)
	project := filepath.Join(root, "project")
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture.response.Namespace = &managedstore.ProjectNamespace{Path: project, ProjectDev: 1, ProjectIno: 2, PolicyDev: 1, PolicyIno: 3}
	snapshot, err := config.ParseManagedProfileSnapshot("default", fixture.response.Profile)
	if err != nil {
		t.Fatal(err)
	}
	fixture.response.Revision = snapshot.Revision()
	state, err := controller.StateDirectory()
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.PrepareState(state); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- controller.Serve(ctx, state) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	client, err := controller.OpenClient(state)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	deadline := time.Now().Add(5 * time.Second)
	for client.Health(ctx) != nil {
		if time.Now().After(deadline) {
			t.Fatal("controller failed to start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	oldLaunch := selectedLaunch
	defer func() { selectedLaunch = oldLaunch }()
	calls := 0
	selectedLaunch = func(ctx context.Context, credential string, request managedlaunch.Request, stdout, _ io.Writer) error {
		calls++
		if credential != managedCredentialPath(state) || request.ProjectID != fixture.response.Project || request.Name != "default" || request.Revision != snapshot.Revision() {
			return fmt.Errorf("wrong authenticated launch request")
		}
		sessions, err := client.Sessions(ctx, false)
		if err != nil || len(sessions) != 1 || sessions[0].SelectedProfile == nil {
			return fmt.Errorf("missing managed session: %v", err)
		}
		selection := sessions[0].SelectedProfile
		if selection.ProjectID != request.ProjectID || selection.Revision != request.Revision || selection.ProfileID != controller.ManagedProfileID(request.ProjectID, request.Name) || selection.Applied || selection.Provenance != "manual/unknown" {
			return fmt.Errorf("incorrect selected session")
		}
		_, err = io.WriteString(stdout, "injected-launch")
		return err
	}
	args := []string{"run", "--backend", "native", "--directory", project, "--syd", managedlaunch.FixedEnginePath, "--config", "default", "--project-id", fixture.response.Project, "--expected-revision", snapshot.Revision(), "--no-network", "--", "/bin/echo"}
	if _, err := managedRun(args, ""); err == nil || calls != 0 {
		t.Fatal("launch succeeded without a review")
	}
	if err := saveManagedReview(state, fixture.response); err != nil {
		t.Fatal(err)
	}
	oldProvenance := lookupSelectedProvenance
	defer func() { lookupSelectedProvenance = oldProvenance }()
	lookupSelectedProvenance = func(context.Context, string, string, string) (selectedProvenance, error) {
		return selectedProvenance{Status: "pending"}, nil
	}
	if _, err := managedRun(args, ""); err == nil || calls != 0 {
		t.Fatal("pending provenance launched")
	}
	lookupSelectedProvenance = oldProvenance
	out, err := managedRun(args, "")
	if err != nil || calls != 1 || !strings.Contains(out, "injected-launch") {
		t.Fatalf("selected launch: %q %v calls=%d", out, err, calls)
	}
	active, err := client.Sessions(ctx, false)
	if err != nil || len(active) != 0 {
		t.Fatalf("session was not completed: %+v %v", active, err)
	}
}
