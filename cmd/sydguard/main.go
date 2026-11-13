// Command sydguard runs AI agents under upstream Syd with a browser UI for
// approving file and network access, applied live to the running agent.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"

	"github.com/Gobd/syd-guard/internal/guest"
	"github.com/Gobd/syd-guard/internal/lima"
	"github.com/Gobd/syd-guard/internal/system"
	"github.com/Gobd/syd-guard/internal/ui"
)

const description = `Runs a command under Syd. Everything it isn't allowed to do shows up in the
approvals UI (http://127.0.0.1:7878); approving or removing a rule applies to
the running agent immediately and is saved to the rules file.

Rules files: <git root>/.sydguard.json by default, --rules NAME for
<git root>/.sydguard/NAME.json, or any path. "All projects" rules live in
~/.config/sydguard/global.json. The sandbox can never write rules files, and
changes made outside sydguard must be trusted before they're used.

On macOS the command runs in a Lima VM (started or created as needed) at the
same project path; one UI covers every VM.`

func main() {
	_ = system.Version() // hash our binary now, before any upgrade replaces it
	if err := app().Run(context.Background(), os.Args); err != nil {
		var exit cli.ExitCoder
		if errors.As(err, &exit) {
			os.Exit(exit.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "sydguard:", err)
		os.Exit(1)
	}
}

func app() *cli.Command {
	one := 1
	return &cli.Command{
		Name:            "sydguard",
		Usage:           "run AI agents under Syd, approve access in a browser",
		UsageText:       "sydguard [flags] [--] command [args...]\nsydguard ui | doctor | setup",
		Description:     description,
		StopOnNthArg:    &one, // everything after the command belongs to it
		HideHelpCommand: true,
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "rules", Usage: "rules file: NAME (= .sydguard/NAME.json) or a path; default .sydguard.json"},
			&cli.BoolFlag{Name: "learn", Usage: "allow everything and save what the command used into the rules file"},
			&cli.IntSliceFlag{Name: "local-port", Usage: "let the agent reach 127.0.0.1:`PORT` (a trusted helper you started, e.g. an auth proxy)"},
			&cli.StringFlag{Name: "vm", Usage: "(macOS) Lima instance; default $SYDGUARD_VM or " + lima.DefaultVM},
			&cli.StringFlag{Name: "lima", Usage: "(macOS) Lima config to create the VM from if missing; default $SYDGUARD_LIMA or built in"},
			&cli.BoolFlag{Name: "from-mac", Hidden: true},
		},
		Action: runAction,
		Commands: []*cli.Command{
			{Name: "ui", Usage: "open the approvals UI", Action: uiAction},
			{Name: "doctor", Usage: "check the Syd engine, namespaces and daemon", Action: doctorAction},
			{Name: "setup", Usage: "install the pinned Syd engine (inside the VM on macOS)", Action: setupAction},
			{Name: "version", Usage: "print the build hash", Action: func(context.Context, *cli.Command) error {
				fmt.Println(system.Version())
				return nil
			}},
			{Name: "daemon", Hidden: true, Action: func(context.Context, *cli.Command) error { return guest.RunDaemon() }},
			{Name: "daemon-ensure", Hidden: true, Action: func(context.Context, *cli.Command) error {
				started, err := guest.EnsureDaemon()
				if err == nil {
					fmt.Println(map[bool]string{true: "started", false: "running"}[started])
				}
				return err
			}},
			{Name: "engine-check", Hidden: true, Action: func(context.Context, *cli.Command) error {
				_, err := guest.FindEngine()
				return err
			}},
			{Name: "ipc-load", Hidden: true, Action: func(_ context.Context, cmd *cli.Command) error {
				return guest.IPCLoad(cmd.Args().Get(0), cmd.Args().Get(1))
			}},
			{Name: "ui-server", Hidden: true, Action: func(context.Context, *cli.Command) error { return ui.RunServer() }},
		},
	}
}

func limaOptions(cmd *cli.Command) lima.Options {
	return lima.Options{
		VM: cmd.String("vm"), LimaFile: cmd.String("lima"), Rules: cmd.String("rules"),
		Learn: cmd.Bool("learn"), LocalPorts: cmd.IntSlice("local-port"), Args: cmd.Args().Slice(),
	}
}

func runAction(_ context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() == 0 {
		return cli.ShowAppHelp(cmd)
	}
	if system.IsMac() {
		return lima.Run(limaOptions(cmd))
	}
	code, err := guest.Run(guest.RunOptions{
		Rules: cmd.String("rules"), Learn: cmd.Bool("learn"),
		LocalPorts: cmd.IntSlice("local-port"), Args: cmd.Args().Slice(), OnReady: func() {
			if cmd.Bool("from-mac") {
				return // the Mac hosts the UI
			}
			if started, err := ui.EnsureServer(); err != nil {
				fmt.Fprintln(os.Stderr, "sydguard: UI:", err)
			} else if started {
				token, _ := ui.Token()
				ui.OpenBrowser(ui.URL(token))
			}
		},
	})
	if err != nil {
		return err
	}
	if code != 0 {
		return cli.Exit("", code)
	}
	return nil
}

func uiAction(_ context.Context, cmd *cli.Command) error {
	if system.IsMac() {
		return lima.OpenUI(true)
	}
	if _, err := guest.EnsureDaemon(); err != nil {
		return err
	}
	if _, err := ui.EnsureServer(); err != nil {
		return err
	}
	token, err := ui.Token()
	if err != nil {
		return err
	}
	ui.OpenBrowser(ui.URL(token))
	fmt.Println(ui.URL(token))
	return nil
}

func doctorAction(_ context.Context, cmd *cli.Command) error {
	if system.IsMac() {
		return lima.Shell(limaOptions(cmd.Root()), "doctor")
	}
	if !guest.Doctor() {
		return cli.Exit("", 1)
	}
	return nil
}

func setupAction(_ context.Context, cmd *cli.Command) error {
	if system.IsMac() {
		_, err := lima.Prepare(limaOptions(cmd.Root())) // installs the engine if missing
		return err
	}
	return guest.Setup()
}
