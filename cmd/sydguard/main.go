package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/Gobd/syd-guard/internal/backend"
	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/doctor"
	"github.com/Gobd/syd-guard/internal/lima"
	"github.com/urfave/cli/v3"
)

const version = "0.0.0-spike"

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, stderr io.Writer) int {
	command := newCommand(out, stderr)
	err := command.Run(context.Background(), append([]string{"sydguard"}, args...))
	if err == nil {
		return 0
	}
	if err.Error() != "" {
		_, _ = fmt.Fprintln(stderr, err)
	}
	var exit cli.ExitCoder
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	return 1
}

func newCommand(out, stderr io.Writer) *cli.Command {
	return &cli.Command{
		Name: "sydguard", Version: version,
		Usage:  "upstream Syd + Go session/policy usability (implementation spike)",
		Writer: out, ErrWriter: stderr,
		// The caller, not the library, owns process exit (also safe for tests).
		ExitErrHandler: func(context.Context, *cli.Command, error) {},
		Action: func(ctx context.Context, c *cli.Command) error {
			if c.Args().Len() > 0 {
				return cli.Exit(fmt.Sprintf("unknown command %q; use sydguard help", c.Args().First()), 2)
			}
			return cli.ShowRootCommandHelp(c)
		},
		Commands: []*cli.Command{
			configCommand(),
			profileCommand(),
			{Name: "version", Usage: "show wrapper version", Action: func(_ context.Context, c *cli.Command) error { _, err := fmt.Fprintln(c.Writer, version); return err }},
			{Name: "doctor", Usage: "inspect native Linux or an existing Lima guest", Flags: []cli.Flag{
				&cli.StringFlag{Name: "backend", Value: "auto", Usage: "auto, native or lima"},
				&cli.StringFlag{Name: "vm", Value: "ai-sandbox", Usage: "explicit Lima instance for this spike"},
				&cli.StringFlag{Name: "syd", Usage: "explicit trusted Syd executable (native only)"},
				&cli.BoolFlag{Name: "json", Usage: "JSON diagnostics"},
			}, Action: doctorAction},
			runCommand(),
			supervisorCommand(),
			sessionsCommand(),
			serveCommand(),
			learnCommand(),
			uiCommand(),
			apiCommand(),
		},
	}
}

func doctorAction(parent context.Context, c *cli.Command) error {
	if c.Args().Len() != 0 {
		return cli.Exit("doctor does not take positional arguments", 2)
	}
	settings, err := config.Load()
	if err != nil {
		return err
	}
	requested := settings.Backend
	if c.IsSet("backend") {
		requested = backend.Kind(c.String("backend"))
	}
	instance := settings.Lima.Instance
	if c.IsSet("vm") {
		instance = c.String("vm")
	}
	kind, err := backend.Select(runtime.GOOS, requested)
	if err != nil {
		return cli.Exit(err.Error(), 2)
	}
	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	defer cancel()
	if kind == backend.Lima {
		if c.String("syd") != "" {
			return cli.Exit("--syd is native-only; configure the guest executable inside the guest", 2)
		}
		guest := []string{"sydguard", "doctor", "--backend", "native"}
		if c.Bool("json") {
			guest = append(guest, "--json")
		}
		argv, err := lima.ShellArgs(instance, guest)
		if err != nil {
			return cli.Exit(err.Error(), 2)
		}
		_, _ = fmt.Fprintf(c.ErrWriter, "Inspecting existing Lima instance %s; doctor does not create/restart/provision VMs.\n", instance)
		cmd := exec.CommandContext(ctx, "limactl", argv...) //nolint:gosec // fixed guest command and validated instance; no shell interpolation
		cmd.Stdout, cmd.Stderr = c.Writer, c.ErrWriter
		if err := cmd.Run(); err != nil {
			return cli.Exit(fmt.Sprintf("Lima doctor failed: %v (install the guest sydguard CLI first)", err), 1)
		}
		return nil
	}
	report := doctor.Probe(ctx, c.String("syd"))
	if c.Bool("json") {
		if err := json.NewEncoder(c.Writer).Encode(report); err != nil {
			return err
		}
	} else {
		if _, err := fmt.Fprintf(c.Writer, "Platform: %s/%s; kernel: %s\n", report.Platform, report.Architecture, report.Kernel); err != nil {
			return err
		}
		for _, check := range report.Checks {
			if _, err := fmt.Fprintf(c.Writer, "[%t] %s\n%s\n", check.OK, check.Name, check.Detail); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(c.Writer, "Prerequisite diagnostics are not a security certification."); err != nil {
			return err
		}
	}
	if !report.LaunchReady {
		return cli.Exit("", 1)
	}
	return nil
}
