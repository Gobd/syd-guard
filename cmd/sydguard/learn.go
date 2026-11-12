package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Gobd/syd-guard/internal/backend"
	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/controller"
	"github.com/Gobd/syd-guard/internal/learning"
	"github.com/Gobd/syd-guard/internal/lima"
	"github.com/Gobd/syd-guard/internal/managedstore"
	"github.com/Gobd/syd-guard/internal/syd"
	"github.com/urfave/cli/v3"
)

func learnCommand() *cli.Command {
	command := runCommand()
	command.Name = "learn"
	command.Usage = "experimental permissive discovery; review candidates before saving"
	command.Flags = append(command.Flags, &cli.BoolFlag{Name: "accept-experimental-risks", Usage: "accept irreversible writes and known hardlink secret bypass"}, &cli.StringFlag{Name: "candidate-name", Value: "default", Usage: "name for review candidate"})
	command.Action = learnAction
	command.Commands = []*cli.Command{
		{Name: "list", Usage: "list private learning candidates", Action: func(_ context.Context, c *cli.Command) error {
			s, err := candidateStore()
			if err != nil {
				return err
			}
			defer func() { _ = s.Close() }()
			values, err := s.Candidates()
			if err != nil {
				return err
			}
			return json.NewEncoder(c.Writer).Encode(values)
		}},
		{Name: "review-export", Usage: "export the full candidate envelope for operator review; does not save", ArgsUsage: "CANDIDATE-ID", Action: showCandidate},
		{Name: "save", Usage: "explicitly save reviewed profile bytes from stdin through managed CAS", Flags: []cli.Flag{&cli.BoolFlag{Name: "experimental"}, &cli.BoolFlag{Name: "yes"}, &cli.BoolFlag{Name: "accept-incomplete"}, &cli.StringFlag{Name: "candidate", Required: true}, &cli.StringFlag{Name: "project-id", Required: true}, &cli.StringFlag{Name: "name", Value: "default"}, &cli.StringFlag{Name: "expected-revision", Required: true}}, Action: saveLearnReview},
		{Name: "review-status", Usage: "inspect pending or bound review evidence", Flags: []cli.Flag{&cli.StringFlag{Name: "review", Required: true}}, Action: showLearnReview},
		{Name: "review-list", Usage: "list review IDs and recovery states", Action: listLearnReviews},
		{Name: "reconcile", Usage: "observe current helper bytes; uncertain CAS remains unknown", Flags: []cli.Flag{&cli.BoolFlag{Name: "experimental"}, &cli.StringFlag{Name: "review", Required: true}}, Action: reconcileLearnReview},
		{Name: "authorize-current", Usage: "separately authorize reviewed current bytes, not the uncertain CAS", Flags: []cli.Flag{&cli.BoolFlag{Name: "experimental"}, &cli.BoolFlag{Name: "yes"}, &cli.BoolFlag{Name: "accept-unknown-operation"}, &cli.StringFlag{Name: "review", Required: true}, &cli.StringFlag{Name: "expected-current-revision", Required: true}}, Action: authorizeCurrentLearnReview},
		{Name: "show", Usage: "show a private candidate and its coverage envelope", ArgsUsage: "CANDIDATE-ID", Action: showCandidate},
	}
	return command
}

func candidateStore() (*learning.Store, error) {
	state, err := config.StateDirectory()
	if err != nil {
		return nil, err
	}
	if err = controller.PrepareState(state); err != nil {
		return nil, err
	}
	return learning.OpenStore(filepath.Join(state, config.PrivateAuthorityFolder, "candidates"))
}

func learnAction(parent context.Context, c *cli.Command) error {
	if !c.Bool("accept-experimental-risks") {
		return cli.Exit("learn requires --accept-experimental-risks: writes are irreversible; preexisting hardlinks bypass known-secret pathname protection; the denylist is not universally secret-safe", 2)
	}
	if c.Args().Len() == 0 || c.String("syd") == "" {
		return cli.Exit("learn requires --syd and -- COMMAND [ARGS...]", 2)
	}
	if err := config.ProfileName(c.String("candidate-name")); err != nil {
		return err
	}
	if len(c.StringSlice("scope"))+len(c.StringSlice("service"))+len(c.StringSlice("read-input"))+len(c.StringSlice("exec-input")) != 0 {
		return cli.Exit("learn does not accept advanced scopes, services or input grants", 2)
	}
	settings, err := config.Load()
	if err != nil {
		return err
	}
	requested := settings.Backend
	if c.IsSet("backend") {
		requested = backend.Kind(c.String("backend"))
	}
	kind, err := backend.Select(runtime.GOOS, requested)
	if err != nil {
		return err
	}
	directory := c.String("directory")
	if directory == "" {
		directory, err = os.Getwd()
		if err != nil {
			return err
		}
	}
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()
	if kind == backend.Lima {
		instance := settings.Lima.Instance
		if c.IsSet("vm") {
			instance = c.String("vm")
		}
		if !c.IsSet("directory") {
			mounts, e := lima.InstanceMounts(ctx, instance)
			if e != nil {
				return e
			}
			directory, err = lima.MapDirectory(filepath.Clean(directory), mounts)
			if err != nil {
				return err
			}
		}
		args := []string{"learn", "--backend", "native", "--directory", directory, "--syd", c.String("syd"), "--candidate-name", c.String("candidate-name"), "--accept-experimental-risks"}
		if c.Bool("no-network") {
			args = append(args, "--no-network")
		}
		if c.Bool("require-pie") {
			args = append(args, "--require-pie")
		}
		if c.String("name") != "" {
			args = append(args, "--name", c.String("name"))
		}
		guest, e := lima.GuestCommand(c.String("guest-sydguard"), c.String("guest-config-home"), args)
		if e != nil {
			return e
		}
		guest = append(guest, "--")
		guest = append(guest, c.Args().Slice()...)
		argv, e := lima.ShellArgs(instance, guest)
		if e != nil {
			return e
		}
		cmd := exec.CommandContext(ctx, "limactl", argv...) //nolint:gosec // validated Lima adapter and direct argument vector
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, c.Writer, c.ErrWriter
		runErr := cmd.Run()
		if err := printGuestLearnInstructions(c.ErrWriter, instance, c.String("guest-sydguard"), c.String("guest-config-home")); err != nil {
			return fmt.Errorf("guest review instructions failed after launch outcome %v: %w", runErr, err)
		}
		return runErr
	}
	if c.String("guest-sydguard") != "" || c.String("guest-config-home") != "" {
		return cli.Exit("guest adapter flags require Lima", 2)
	}
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		return fmt.Errorf("learn requires an unprivileged user")
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		return err
	}
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(c.ErrWriter, "EXPERIMENTAL LEARN: writes are irreversible; preexisting hardlinks can expose secrets. A denylist is not a universal secret classifier. Candidates are permission checks, not successful I/O or complete coverage; review before saving.")
	if c.Bool("no-network") {
		return recordLearning(ctx, syd.RunOptions{Engine: c.String("syd"), Directory: directory, Args: c.Args().Slice(), Bootstrap: true, Stdin: os.Stdin, Stdout: c.Writer, Stderr: c.ErrWriter, RequirePIE: c.Bool("require-pie")}, c.String("candidate-name"), c.ErrWriter, nil, nil)
	}
	state, err := controller.StateDirectory()
	if err != nil {
		return err
	}
	client, err := controller.OpenClient(state)
	if err != nil {
		return err
	}
	defer client.Close()
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if err := client.Ensure(ctx, executable); err != nil {
		if saveErr := saveUnstartedLearningResult(directory, c.String("candidate-name"), c.ErrWriter, ctx.Err() != nil); saveErr != nil {
			return fmt.Errorf("controller startup failed (%v) and candidate persistence failed: %w", err, saveErr)
		}
		return err
	}
	registered, err := client.RegisterTransparentLearning(ctx, directory, c.String("name"), c.Args().Slice())
	if err != nil {
		if saveErr := saveUnstartedLearningResult(directory, c.String("candidate-name"), c.ErrWriter, ctx.Err() != nil); saveErr != nil {
			return fmt.Errorf("session registration failed (%v) and candidate persistence failed: %w", err, saveErr)
		}
		return err
	}
	var savedCandidate bool
	runErr := runTransparent(ctx, c, executable, state, directory, registered, &savedCandidate)
	if !savedCandidate {
		if saveErr := saveUnknownLearningResult(directory, c.String("candidate-name"), c.ErrWriter, ctx.Err() != nil); saveErr != nil {
			runErr = fmt.Errorf("learning supervisor outcome %v and candidate persistence failed: %w", runErr, saveErr)
		}
	}
	finishCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := client.Complete(finishCtx, registered); err != nil {
		return fmt.Errorf("learning session cleanup failed after workload outcome %v: %w", runErr, err)
	}
	return runErr
}

// recordLearning persists the full candidate even on an abnormal workload or
// failed delivery. closeDials seals and quiesces the controller gateway first.
func recordLearning(ctx context.Context, options syd.RunOptions, name string, stderr io.Writer, closeDials func() (controller.LearningDials, error), onStored func(string) error) error {
	store, err := candidateStore()
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()
	var collector *learning.Collector
	options.OnBootstrapStart = func(temporary string, protected []string) error {
		var e error
		collector, e = learning.New(learning.Policy{Name: name, Temporary: temporary, PolicyDirectory: filepath.Join(options.Directory, ".sydguard"), ExcludedRoots: protected, RateLimitDisabled: true})
		return e
	}
	options.OnTrustedLog = func(reader io.Reader) error { return collector.Drain(reader) }
	var processSignal os.Signal
	options.OnExit = func(_ int, signal os.Signal) { processSignal = signal }
	code, runErr := syd.Run(ctx, options)
	var dials controller.LearningDials
	var deliveryErr error
	if closeDials != nil {
		dials, deliveryErr = closeDials()
		if dials.Dropped && deliveryErr == nil {
			deliveryErr = errors.New("public dial observation limit exceeded")
		}
	}
	candidate := learning.ProfileCandidate{Profile: config.Profile{Version: 1, Name: name, Files: []config.FileRule{}, Network: []config.NetworkRule{}}, Kind: "permission-check-candidate", Incomplete: true, Reasons: []string{"bootstrap-not-started", "log-not-drained"}}
	if runErr != nil || code != 0 || ctx.Err() != nil {
		candidate.Reasons = append(candidate.Reasons, "abnormal-exit")
	}
	if deliveryErr != nil {
		candidate.Reasons = append(candidate.Reasons, "delivery-error")
	}
	if collector != nil {
		if closeDials == nil {
			collector.NetworkNotObserved()
		} else {
			collector.CleanupNotConfirmed()
		}
		for _, dial := range dials.Targets {
			if e := collector.OnPublicDial(dial.Host, dial.Port, dial.Transport); e != nil {
				deliveryErr = e
			}
		}
		outcome := learning.Outcome{ExitCode: code, Err: runErr, Signal: processSignal, Cancelled: ctx.Err() != nil, DeliveryError: deliveryErr}
		if runErr != nil && strings.Contains(runErr.Error(), "trusted log") {
			outcome.DeliveryError = runErr
		}
		collector.FinishOutcome(outcome)
		candidate = collector.Snapshot()
	}
	signalName := ""
	if processSignal != nil {
		signalName = processSignal.String()
	}
	id, err := store.SaveCandidate(learning.CandidateRecord{Project: options.Directory, Candidate: candidate, ExitCode: code, Cancelled: ctx.Err() != nil, Signal: signalName, LaunchError: runErr != nil})
	if err != nil {
		return fmt.Errorf("candidate persistence failed: %w; workload result may be lost", err)
	}
	_, _ = fmt.Fprintf(stderr, "Private candidate %s (incomplete=%t); inspect with sydguard learn show %s in this Linux configuration authority. No permission was saved or applied.\n", id, candidate.Incomplete, id)
	if onStored != nil {
		if err := onStored(id); err != nil {
			return fmt.Errorf("candidate %s saved but supervisor confirmation failed: %w", id, err)
		}
	}
	if deliveryErr != nil {
		return fmt.Errorf("candidate recorded with incomplete public dial delivery: %w", deliveryErr)
	}
	if runErr != nil {
		return runErr
	}
	if code != 0 {
		return cli.Exit("", code)
	}
	return nil
}

func showCandidate(_ context.Context, c *cli.Command) error {
	if c.Args().Len() != 1 {
		return fmt.Errorf("candidate ID required")
	}
	s, err := candidateStore()
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	value, err := s.Candidate(c.Args().First())
	if err != nil {
		return err
	}
	return json.NewEncoder(c.Writer).Encode(value)
}

func saveLearnReview(ctx context.Context, c *cli.Command) error {
	client, err := managedClientFor(c, true)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(c.Reader, managedstore.Limit+1))
	if err != nil {
		return err
	}
	if len(data) > managedstore.Limit {
		return fmt.Errorf("reviewed profile too large")
	}
	s, err := candidateStore()
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	return s.WithReviewLockContext(ctx, func() error {
		pending, err := s.BeginReview(c.String("candidate"), c.String("project-id"), c.String("name"), c.String("expected-revision"), data, c.Bool("accept-incomplete"))
		if err != nil {
			return err
		}
		if err := managedOutput(func() error {
			_, e := fmt.Fprintf(c.ErrWriter, "Review %s durably pending; permission-check evidence is not successful I/O or complete coverage.\n", pending.ID)
			return e
		}); err != nil {
			finishErr := s.CompleteReview(pending.ID, "rejected", pending.ProjectID, pending.Name, "", nil)
			if finishErr != nil {
				return fmt.Errorf("%w: review %s not submitted; pending record unresolved: %v; output: %w", managedstore.ErrNotSubmitted, pending.ID, finishErr, err)
			}
			return fmt.Errorf("%w: review %s not submitted because pending ID output failed; use learn review-list: %w", managedstore.ErrNotSubmitted, pending.ID, err)
		}
		response, err := client.Replace(ctx, pending.ProjectID, pending.Name, pending.ExpectedRevision, pending.ReviewedBytes)
		if err != nil {
			if errors.Is(err, managedstore.ErrConflict) || errors.Is(err, managedstore.ErrNotSubmitted) {
				if finishErr := s.CompleteReview(pending.ID, "rejected", pending.ProjectID, pending.Name, "", nil); finishErr != nil {
					return fmt.Errorf("review %s pending outcome could not be durably closed: %w", pending.ID, finishErr)
				}
				return fmt.Errorf("review %s rejected: %w", pending.ID, err)
			}
			return fmt.Errorf("review %s CAS outcome unknown; use learn reconcile and review-list before any retry: %w", pending.ID, err)
		}
		if err := s.CompleteReview(pending.ID, "bound", response.Project, response.Name, response.Revision, response.Profile); err != nil {
			return fmt.Errorf("review %s outcome unknown after helper return; reconcile before retry: %w", pending.ID, err)
		}
		outputErr := managedOutput(func() error {
			return json.NewEncoder(c.Writer).Encode(struct {
				Review   string `json:"review"`
				Project  string `json:"project"`
				Name     string `json:"name"`
				Revision string `json:"revision"`
			}{pending.ID, response.Project, response.Name, response.Revision})
		})
		if outputErr != nil {
			return fmt.Errorf("%w: review %s committed and bound but output failed; use learn review-list and authenticate a fresh helper snapshot: %w", managedstore.ErrIndeterminate, pending.ID, outputErr)
		}
		return nil
	})
}

func reconcileLearnReview(ctx context.Context, c *cli.Command) error {
	client, err := managedClientFor(c, false)
	if err != nil {
		return err
	}
	s, err := candidateStore()
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	return s.WithReviewLockContext(ctx, func() error {
		pending, result, err := s.Review(c.String("review"))
		if err != nil {
			return err
		}
		if result != nil {
			return fmt.Errorf("review already resolved: %s", result.Status)
		}
		response, err := readCurrentLearnSnapshot(ctx, client, pending)
		if err != nil {
			return err
		}
		return json.NewEncoder(c.Writer).Encode(struct {
			Review          string          `json:"review"`
			OperationStatus string          `json:"operation_status"`
			CurrentRevision string          `json:"current_revision"`
			MatchesReviewed bool            `json:"matches_reviewed_bytes"`
			Profile         json.RawMessage `json:"profile"`
		}{pending.ID, "unknown", response.Revision, bytes.Equal(response.Profile, pending.ReviewedBytes), response.Profile})
	})
}

func showLearnReview(_ context.Context, c *cli.Command) error {
	if c.Args().Len() != 0 {
		return fmt.Errorf("review status takes no positional arguments")
	}
	s, err := candidateStore()
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	pending, result, err := s.Review(c.String("review"))
	if err != nil {
		return err
	}
	candidate, err := s.Candidate(pending.CandidateID)
	if err != nil {
		return err
	}
	return json.NewEncoder(c.Writer).Encode(struct {
		Pending   learning.ReviewPending   `json:"pending"`
		Result    *learning.ReviewResult   `json:"result"`
		Candidate learning.CandidateRecord `json:"candidate"`
	}{pending, result, candidate})
}

// saveUnknownLearningResult records a failed launcher handoff without claiming
// that an unacknowledged supervisor did or did not persist another candidate.
func saveUnknownLearningResult(directory, name string, stderr io.Writer, cancelled bool) error {
	return saveFailedLearningResult(directory, name, stderr, cancelled, "supervisor-result-unknown")
}

func saveUnstartedLearningResult(directory, name string, stderr io.Writer, cancelled bool) error {
	return saveFailedLearningResult(directory, name, stderr, cancelled, "bootstrap-not-started")
}

func saveFailedLearningResult(directory, name string, stderr io.Writer, cancelled bool, reason string) error {
	s, err := candidateStore()
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	candidate := learning.ProfileCandidate{Profile: config.Profile{Version: 1, Name: name, Files: []config.FileRule{}, Network: []config.NetworkRule{}}, Kind: "permission-check-candidate", Incomplete: true, Reasons: []string{"abnormal-exit", "log-not-drained", reason}}
	id, err := s.SaveCandidate(learning.CandidateRecord{Project: directory, Candidate: candidate, ExitCode: 1, Cancelled: cancelled, LaunchError: true})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stderr, "Private candidate %s records %s; inspect the full envelope before review.\n", id, reason)
	return nil
}

func readCurrentLearnSnapshot(ctx context.Context, client managedClient, pending learning.ReviewPending) (managedstore.Response, error) {
	response, err := client.Read(ctx, pending.ProjectID, pending.Name)
	if err != nil {
		return response, err
	}
	snapshot, err := config.ParseManagedProfileSnapshot(pending.Name, response.Profile)
	if err != nil || response.Project != pending.ProjectID || response.Name != pending.Name || snapshot.Revision() != response.Revision {
		return managedstore.Response{}, errors.New("helper current snapshot binding invalid")
	}
	return response, nil
}

func authorizeCurrentLearnReview(ctx context.Context, c *cli.Command) error {
	if !c.Bool("accept-unknown-operation") {
		return errors.New("separate current authorization requires --accept-unknown-operation; it does not establish the uncertain CAS outcome")
	}
	client, err := managedClientFor(c, true)
	if err != nil {
		return err
	}
	s, err := candidateStore()
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	return s.WithReviewLockContext(ctx, func() error {
		pending, result, err := s.Review(c.String("review"))
		if err != nil {
			return err
		}
		if result != nil {
			return fmt.Errorf("review already resolved: %s", result.Status)
		}
		response, err := readCurrentLearnSnapshot(ctx, client, pending)
		if err != nil {
			return err
		}
		if response.Revision != c.String("expected-current-revision") {
			return errors.New("current snapshot changed; inspect it again before independent authorization")
		}
		if err := s.AuthorizeCurrent(pending.ID, response.Project, response.Name, response.Revision, response.Profile); err != nil {
			return fmt.Errorf("current authorization outcome uncertain for review %s: %w", pending.ID, err)
		}
		outputErr := managedOutput(func() error {
			return json.NewEncoder(c.Writer).Encode(map[string]string{"review": pending.ID, "status": "current-authorized", "operation_status": "unknown", "revision": response.Revision})
		})
		if outputErr != nil {
			return fmt.Errorf("%w: current snapshot independently authorized for review %s but output failed; inspect review-list: %w", managedstore.ErrIndeterminate, pending.ID, outputErr)
		}
		return nil
	})
}

func listLearnReviews(_ context.Context, c *cli.Command) error {
	if c.Args().Len() != 0 {
		return errors.New("review-list takes no positional arguments")
	}
	s, err := candidateStore()
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	values, err := s.ReviewSummaries()
	if err != nil {
		return err
	}
	return json.NewEncoder(c.Writer).Encode(values)
}

func shellQuoteArgument(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func printGuestLearnInstructions(writer io.Writer, instance, executable, configHome string) error {
	commands := [][]string{{"learn", "list"}, {"learn", "show", "CANDIDATE_ID"}, {"learn", "review-list"}}
	if _, err := fmt.Fprintln(writer, "Candidates and reviews are in the guest configuration used for this launch; replace CANDIDATE_ID below:"); err != nil {
		return err
	}
	for _, command := range commands {
		guest, err := lima.GuestCommand(executable, configHome, command)
		if err != nil {
			return err
		}
		argv, err := lima.ShellArgs(instance, guest)
		if err != nil {
			return err
		}
		words := []string{"limactl"}
		for _, value := range argv {
			words = append(words, shellQuoteArgument(value))
		}
		if _, err := fmt.Fprintln(writer, strings.Join(words, " ")); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(writer, "Use the same guest executable and XDG_CONFIG_HOME for learn review-export, save, review-status, reconcile and authorize-current.")
	return err
}
