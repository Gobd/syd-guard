//go:build linux || darwin

package main

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/controller"
	"github.com/Gobd/syd-guard/internal/managedstore"
)

func TestManagedReviewCommandRequiresExactReviewedSnapshot(t *testing.T) {
	fixture, _ := managedCommandTestSetup(t)
	fixture.response.Namespace = &managedstore.ProjectNamespace{Path: "/project", ProjectDev: 1, ProjectIno: 2, PolicyDev: 1, PolicyIno: 3}
	snapshot, err := config.ParseManagedProfileSnapshot("default", fixture.response.Profile)
	if err != nil {
		t.Fatal(err)
	}
	fixture.response.Revision = snapshot.Revision()
	args := []string{"managed", "--experimental", "review", "--project-id", fixture.response.Project, "--expected-revision", fixture.response.Revision, "--yes"}
	out, err := managedRun(args, "")
	if err != nil || !strings.Contains(out, `"profile":`) {
		t.Fatalf("review: %q %v", out, err)
	}
	state, err := controller.StateDirectory()
	if err != nil {
		t.Fatal(err)
	}
	if err := requireManagedReview(state, fixture.response); err != nil {
		t.Fatal(err)
	}
	args[len(args)-2] = strings.Repeat("b", 64)
	if _, err := managedRun(args, ""); !errors.Is(err, managedstore.ErrConflict) {
		t.Fatalf("expected conflict: %v", err)
	}
	fixture.response.Project = strings.Repeat("c", 64)
	args[len(args)-2] = snapshot.Revision()
	if _, err := managedRun(args, ""); err == nil {
		t.Fatal("accepted mismatched helper selection")
	}
}

func TestManagedReviewBindsExactSnapshotAndEnrollment(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	state, err := os.MkdirTemp(home, ".sg-review-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(state) })
	data := []byte(`{"version":1,"name":"default","files":[],"network":[]}`)
	snapshot, err := config.ParseManagedProfileSnapshot("default", data)
	if err != nil {
		t.Fatal(err)
	}
	response := managedstore.Response{Project: strings.Repeat("a", 64), Name: "default", Revision: snapshot.Revision(), Profile: data, Namespace: &managedstore.ProjectNamespace{Path: "/project", ProjectDev: 1, ProjectIno: 2, PolicyDev: 1, PolicyIno: 3}}
	if err := requireManagedReview(state, response); err == nil {
		t.Fatal("accepted without review")
	}
	if err := saveManagedReview(state, response); err != nil {
		t.Fatal(err)
	}
	if err := requireManagedReview(state, response); err != nil {
		t.Fatal(err)
	}
	changed := response
	changed.Project = strings.Repeat("b", 64)
	if err := requireManagedReview(state, changed); err == nil {
		t.Fatal("review survived enrollment change")
	}
	changed = response
	newNamespace := *response.Namespace
	newNamespace.PolicyIno++
	changed.Namespace = &newNamespace
	if err := requireManagedReview(state, changed); err == nil {
		t.Fatal("review survived namespace change")
	}
	changed = response
	changed.Profile = []byte(`{"version":1,"name":"default","files":[],"network":[]} `)
	snapshot, err = config.ParseManagedProfileSnapshot("default", changed.Profile)
	if err != nil {
		t.Fatal(err)
	}
	changed.Revision = snapshot.Revision()
	if err := requireManagedReview(state, changed); err == nil {
		t.Fatal("review survived exact-byte revision change")
	}
	path, err := reviewFile(state, response.Project, response.Name)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", path); err != nil {
		t.Fatal(err)
	}
	if err := requireManagedReview(state, response); err == nil {
		t.Fatal("accepted symlink review receipt")
	}
}
