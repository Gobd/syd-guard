package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Gobd/syd-guard/internal/backend"
	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/controller"
	"github.com/Gobd/syd-guard/internal/files"
	"github.com/Gobd/syd-guard/internal/lima"
	"github.com/Gobd/syd-guard/internal/session"
	"github.com/Gobd/syd-guard/internal/syd"
	"github.com/urfave/cli/v3"
)

func runCommand() *cli.Command {
	return &cli.Command{Name: "run", Usage: "confined foreground session with transparent network approval", ArgsUsage: "-- COMMAND [ARGS...]", Flags: []cli.Flag{
		&cli.StringFlag{Name: "backend", Value: "auto"},
		&cli.StringFlag{Name: "vm", Value: "ai-sandbox"},
		&cli.StringFlag{Name: "guest-sydguard", Usage: "absolute guest CLI path for Lima delegation"},
		&cli.StringFlag{Name: "guest-config-home", Usage: "absolute guest XDG_CONFIG_HOME for Lima delegation"},
		&cli.StringFlag{Name: "syd", Usage: "explicit tested Linux Syd 3.59.0 executable"},
		&cli.StringFlag{Name: "directory", Usage: "explicit existing Linux working directory"},
		&cli.StringFlag{Name: "name", Usage: "friendly session label; duplicates receive numeric suffixes"},
		&cli.BoolFlag{Name: "network-proxy", Usage: "experimental explicit proxy adapter"},
		&cli.BoolFlag{Name: "no-network", Usage: "immutable no-network mode"},
		&cli.StringSliceFlag{Name: "service", Usage: "trusted exact service: lambdap-auth=127.0.0.1:PORT; repeatable"},
		&cli.StringSliceFlag{Name: "read-input", Usage: "trusted exact regular file readable by the workload; repeatable"},
		&cli.StringSliceFlag{Name: "exec-input", Usage: "trusted exact regular file readable and executable by the workload; repeatable"},
		&cli.StringSliceFlag{Name: "scope", Usage: "explicit filesystem ceiling eligible for live learning/approval; repeatable"},
	}, Action: runAction}
}

var namespaceName = regexp.MustCompile(`^sg-[0-9a-f]{6}$`)

func runTransparent(ctx context.Context, c *cli.Command, executable, state, directory string, registered session.Session) error {
	if !namespaceName.MatchString(registered.Namespace) || os.Getuid() <= 0 || os.Getgid() <= 0 {
		return fmt.Errorf("invalid namespace or non-root user identity")
	}
	runs := filepath.Join(state, "runs")
	if err := os.MkdirAll(runs, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(runs)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("unsafe run authority directory")
	}
	authority, err := os.MkdirTemp(runs, "run-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(authority) }()
	goScopes, err := goEligibility(ctx, directory, state)
	if err != nil {
		return err
	}
	scopes := append([]string{directory}, goScopes...)
	scopes = append(scopes, c.StringSlice("scope")...)
	spec := supervisorSpec{Engine: c.String("syd"), Directory: directory, State: state, SessionID: registered.ID, TransitDNS: registered.TransitDNS, Args: c.Args().Slice(), Scopes: scopes, ReadInputs: c.StringSlice("read-input"), ExecInputs: c.StringSlice("exec-input"), Environment: os.Environ()}
	data, err := json.Marshal(spec)
	if err != nil {
		return err
	}
	path := filepath.Join(authority, "spec.json")
	if err = os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(c.ErrWriter, "Session %s (%s): transparent network; approvals apply on retry.\n", registered.Name, registered.ID)
	command := exec.CommandContext(ctx, "/usr/bin/sudo", "-n", "--", "/usr/sbin/ip", "netns", "exec", registered.Namespace, "/usr/bin/setpriv", "--reuid", fmt.Sprint(os.Getuid()), "--regid", fmt.Sprint(os.Getgid()), "--clear-groups", "--no-new-privs", "--bounding-set=-all", "--", executable, "supervise", path) //nolint:gosec // fixed privileged argv; generated namespace and numeric identities validated above
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = 5 * time.Second
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, c.Writer, c.ErrWriter
	if err = command.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() >= 0 {
			return cli.Exit("", exit.ExitCode())
		}
		return err
	}
	return nil
}

func runAction(parent context.Context, c *cli.Command) error {
	if c.Args().Len() == 0 {
		return cli.Exit("usage: sydguard run -- COMMAND [ARGS...]", 2)
	}
	if c.Bool("network-proxy") && c.Bool("no-network") || len(c.StringSlice("service")) > 0 && (c.Bool("network-proxy") || c.Bool("no-network")) {
		return cli.Exit("--network-proxy, --no-network and --service cannot be combined", 2)
	}
	// Explicit engine selection until promotion/install capability is implemented.
	if c.String("syd") == "" {
		return cli.Exit("select the tested engine with --syd; no unconfined fallback", 2)
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
			mounts, err := lima.InstanceMounts(ctx, instance)
			if err != nil {
				return err
			}
			directory, err = lima.MapDirectory(filepath.Clean(directory), mounts)
			if err != nil {
				return err
			}
		}
		guest, err := lima.GuestCommand(c.String("guest-sydguard"), c.String("guest-config-home"), []string{c.Name, "--backend", "native", "--directory", directory, "--syd", c.String("syd")})
		if err != nil {
			return err
		}
		if c.String("name") != "" {
			guest = append(guest, "--name", c.String("name"))
		}
		if c.Bool("network-proxy") {
			guest = append(guest, "--network-proxy")
		}
		if c.Bool("no-network") {
			guest = append(guest, "--no-network")
		}
		for _, service := range c.StringSlice("service") {
			guest = append(guest, "--service", service)
		}
		for _, scope := range c.StringSlice("scope") {
			guest = append(guest, "--scope", scope)
		}
		for _, input := range c.StringSlice("read-input") {
			guest = append(guest, "--read-input", input)
		}
		for _, input := range c.StringSlice("exec-input") {
			guest = append(guest, "--exec-input", input)
		}
		guest = append(guest, "--")
		guest = append(guest, c.Args().Slice()...)
		argv, err := lima.ShellArgs(instance, guest)
		if err != nil {
			return err
		}
		// Initial adapter uses an existing VM and mirrored host paths. Automatic
		// creation/mapping/provisioning are not claimed by this foreground spike.
		command := exec.CommandContext(ctx, "limactl", argv...) //nolint:gosec // validated instance, direct guest argv and explicit workspace
		command.Stdin, command.Stdout, command.Stderr = os.Stdin, c.Writer, c.ErrWriter
		if err := command.Run(); err != nil {
			return err
		}
		return nil
	}
	if c.String("guest-sydguard") != "" || c.String("guest-config-home") != "" {
		return cli.Exit("guest adapter flags require Lima", 2)
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		return err
	}
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		return err
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
		return err
	}
	transparent := !c.Bool("network-proxy") && !c.Bool("no-network")
	var registered session.Session
	if transparent {
		services := make([]controller.Service, 0, len(c.StringSlice("service")))
		for _, declaration := range c.StringSlice("service") {
			name, endpoint, ok := strings.Cut(declaration, "=")
			if !ok {
				return cli.Exit("invalid service declaration", 2)
			}
			services = append(services, controller.Service{Name: name, Endpoint: endpoint})
		}
		registered, err = client.RegisterTransparent(ctx, directory, c.String("name"), c.Args().Slice(), services)
	} else {
		registered, err = client.RegisterProxy(ctx, directory, c.String("name"), c.Args().Slice(), c.Bool("network-proxy"))
	}
	if err != nil {
		return err
	}
	defer func() {
		finishCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := client.Complete(finishCtx, registered); err != nil {
			_, _ = fmt.Fprintf(c.ErrWriter, "Session completion report failed: %v\n", err)
		}
	}()
	if transparent {
		return runTransparent(ctx, c, executable, state, directory, registered)
	}
	_, _ = fmt.Fprintf(c.ErrWriter, "Session %s (%s): confined foreground; file learning ceilings=%d; direct network remains denied.\n", registered.Name, registered.ID, len(c.StringSlice("scope")))
	options := syd.RunOptions{Engine: c.String("syd"), Directory: directory, Args: c.Args().Slice(), Stdin: os.Stdin, Stdout: c.Writer, Stderr: c.ErrWriter, Gateway: registered.Gateway, Scopes: c.StringSlice("scope"), ReadInputs: c.StringSlice("read-input"), ExecInputs: c.StringSlice("exec-input")}
	if len(options.Scopes) > 0 {
		options.OnReady = func(socket string, scopes, protected []string) error {
			return client.FileReady(ctx, registered.ID, files.Context{Socket: socket, Scopes: scopes, Protected: protected})
		}
		options.OnEvent = func(data []byte) error {
			for _, event := range files.ParseEvents(data) {
				if !syd.FileCapability(event.Capability) {
					continue
				}
				eventCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				err := client.FileEvent(eventCtx, registered.ID, event)
				cancel()
				if err != nil {
					return err
				}
			}
			return nil
		}
	}
	code, err := syd.Run(ctx, options)
	if err != nil {
		return err
	}
	if code != 0 {
		return cli.Exit("", code)
	}
	return nil
}
