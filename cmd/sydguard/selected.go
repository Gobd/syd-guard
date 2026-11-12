package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/controller"
	"github.com/Gobd/syd-guard/internal/managedlaunch"
	"github.com/Gobd/syd-guard/internal/session"
	"github.com/urfave/cli/v3"
)

const selectedFinishTimeout = 3 * time.Second

var selectedLaunch = launchManagedHelper

func runSelected(ctx context.Context, c *cli.Command, directory string) error {
	if c.String("syd") != managedlaunch.FixedEnginePath {
		return fmt.Errorf("selected replay requires the fixed immutable engine %s", managedlaunch.FixedEnginePath)
	}
	store, err := candidateStore()
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()
	// Initial subset keeps review authorization serialized through launch. A
	// future ready-ACK handoff can release this before workload completion; do
	// not permit an uncertain review to race the selected launch in the meantime.
	return store.WithReviewLockContext(ctx, func() error {
		return runSelectedAuthorized(context.WithValue(ctx, selectedProvenanceStoreKey{}, store), c, directory)
	})
}

func runSelectedAuthorized(ctx context.Context, c *cli.Command, directory string) error {
	if err := managedCheckPlatform(); err != nil {
		return err
	}
	state, err := controller.StateDirectory()
	if err != nil {
		return err
	}
	if err := controller.PrepareState(state); err != nil {
		return err
	}
	if err := controller.PrepareState(filepath.Join(state, config.PrivateAuthorityFolder)); err != nil {
		return err
	}
	client, err := managedOpen(managedCredentialPath(state))
	if err != nil {
		return err
	}
	response, err := client.Read(ctx, c.String("project-id"), c.String("config"))
	if err != nil {
		return err
	}
	if response.Namespace == nil || response.Project != c.String("project-id") || response.Name != c.String("config") || response.Revision != c.String("expected-revision") {
		return fmt.Errorf("authenticated selected snapshot does not match requested revision")
	}
	// This is a user-facing selection check only. The launcher uses the helper's
	// held generation-bearing objects, never this display path, as authority.
	if response.Namespace.Path != directory || pathsOverlap(directory, state) {
		return fmt.Errorf("selected registration does not match the requested project, or overlaps private state")
	}
	if err := requireManagedReview(state, response); err != nil {
		return err
	}
	provenance, err := checkedSelectedProvenance(ctx, response.Project, response.Name, response.Revision)
	if err != nil {
		return err
	}
	snapshot, err := config.ParseManagedProfileSnapshot(response.Name, response.Profile)
	if err != nil {
		return err
	}
	// Validate logical subset before creating a session. Path resolution happens
	// again only in the launcher-created pinned mount view.
	profile := snapshot.Profile()
	if len(profile.Network) != 0 {
		return fmt.Errorf("selected profile contains unsupported network intent")
	}
	for _, rule := range profile.Files {
		if filepath.IsAbs(rule.Path) || filepath.Clean(rule.Path) != rule.Path || len(rule.Access) != 1 || rule.Access[0] != "read" || len(rule.Path) > 0 && rule.Path[0] == '~' {
			return fmt.Errorf("selected profile supports only project-relative read rules")
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	configHome, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	request := managedlaunch.Request{ProjectID: response.Project, Name: response.Name, Revision: response.Revision, Engine: c.String("syd"), Home: home, ConfigHome: configHome, Args: c.Args().Slice(), RequirePIE: c.Bool("require-pie")}
	connection, err := controller.OpenClient(state)
	if err != nil {
		return err
	}
	defer connection.Close()
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if err := connection.Ensure(ctx, executable); err != nil {
		return err
	}
	selection := session.SelectedProfile{ProjectID: response.Project, ProfileID: controller.ManagedProfileID(response.Project, response.Name), Name: response.Name, Revision: response.Revision, Provenance: provenance.Status, ProvenanceDetail: provenance.Detail}
	registered, err := connection.RegisterManaged(ctx, response.Namespace.Path, c.String("name"), request.Args, selection)
	if err != nil {
		return err
	}
	defer func() {
		finishCtx, cancel := context.WithTimeout(context.Background(), selectedFinishTimeout)
		defer cancel()
		if err := connection.Complete(finishCtx, registered); err != nil {
			_, _ = fmt.Fprintf(c.ErrWriter, "Session completion report failed: %v\n", err)
		}
	}()
	_, _ = fmt.Fprintf(c.ErrWriter, "Session %s (%s): reviewed managed selection requested; provenance=%s; learning completeness not asserted; no network, stdin /dev/null.\n", registered.Name, registered.ID, provenance.Status)
	if provenance.Detail != "" {
		_, _ = fmt.Fprintf(c.ErrWriter, "Candidate provenance: %s\n", provenance.Detail)
	}
	if err := selectedLaunch(ctx, managedCredentialPath(state), request, c.Writer, c.ErrWriter); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() >= 0 {
			return cli.Exit("", exit.ExitCode())
		}
		return err
	}
	return nil
}
