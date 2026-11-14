// Command sydguard runs AI agents under upstream Syd with a browser UI for
// approving file and network access, applied live to the running agent.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/urfave/cli/v3"

	"github.com/Gobd/syd-guard/internal/guest"
	"github.com/Gobd/syd-guard/internal/lima"
	"github.com/Gobd/syd-guard/internal/system"
	"github.com/Gobd/syd-guard/internal/ui"
)

const description = `Runs a command under Syd. Everything it isn't allowed to do shows up in the
approvals UI (http://127.0.0.1:7878); approving or removing a rule applies to
the running agent immediately and is saved to the rules file.

Only the folder you launch in (plus /tmp) is writable. Rules files:
./.sydguard.json by default, --rules NAME for ./.sydguard/NAME.json, or any path. "All projects" rules live in
~/.config/sydguard/global.json. The sandbox can never write rules files, and
changes made outside sydguard must be trusted before they're used.

Commands run in a Lima VM by default on both Linux and macOS. Native Linux
execution requires --backend native (or an explicit backend config setting).
Inside an existing Lima guest, native is the default to avoid nested VMs.
One UI, on the machine you run sydguard on, covers every VM.`

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
			&cli.BoolFlag{Name: "landlock", Usage: "enable a fixed filesystem ceiling (config landlock.read/write); --landlock=false disables it"},
			&cli.IntSliceFlag{Name: "local-port", Usage: "let the agent reach 127.0.0.1:`PORT` (a trusted helper you started, e.g. an auth proxy)"},
			&cli.StringSliceFlag{Name: "pass-env", Usage: "keep environment variable `NAME` for the agent (Syd strips some by default; repeatable)"},
			&cli.StringFlag{Name: "backend", Usage: "lima (default) or native (explicit Linux opt-in); $SYDGUARD_BACKEND or config"},
			&cli.StringFlag{Name: "vm", Usage: "Lima VM name ($SYDGUARD_VM, config, or " + lima.DefaultVM + ")"},
			&cli.StringFlag{Name: "lima", Usage: "Lima file to create the VM from if missing ($SYDGUARD_LIMA, config, or built in)"},
		},
		Action: runAction,
		Commands: []*cli.Command{
			{
				Name: "ui", Usage: "the approvals UI: open it (starting it if needed), or status/start/stop/restart",
				Action: uiAction,
				Commands: []*cli.Command{
					{Name: "status", Usage: "running? which build?", Action: func(context.Context, *cli.Command) error { ui.UIStatus(); return nil }},
					{Name: "start", Usage: "start the UI server (no browser)", Action: func(context.Context, *cli.Command) error { return ui.StartUI() }},
					{Name: "stop", Usage: "stop the UI server only (agents keep running)", Action: func(context.Context, *cli.Command) error { return ui.StopUI() }},
					{Name: "restart", Usage: "restart the UI server and daemons with this build (agents keep running)", Action: func(context.Context, *cli.Command) error {
						return ui.Restart()
					}},
				},
			},
			{
				Name: "vm", Usage: "Lima VMs: a shell (or `-- command`) in the VM outside the sandbox, or list/start/stop",
				UsageText: "sydguard vm                    shell in the VM at this path (outside the sandbox)\n" +
					"sydguard vm -- command [args]  run a command there\n" +
					"sydguard vm list | start [NAME] | stop [NAME...]",
				StopOnNthArg: &one, Action: vmAction,
				Commands: []*cli.Command{
					{Name: "list", Usage: "VMs: running or stopped, agents, sydguard build", Action: func(context.Context, *cli.Command) error {
						ui.ListMachines()
						return nil
					}},
					{
						Name: "start", Usage: "start (or create) a VM and install sydguard + its engine", UsageText: "sydguard vm start [NAME]",
						Action: func(_ context.Context, cmd *cli.Command) error {
							o := limaOptions(cmd.Root())
							if n := cmd.Args().First(); n != "" {
								o.VM = n
							}
							vm, err := lima.Prepare(o)
							if err == nil {
								fmt.Println("ready:", vm)
							}
							return err
						},
					},
					{
						Name: "stop", Usage: "shut down VMs (all running ones by default; refuses while agents run)", UsageText: "sydguard vm stop [NAME...]",
						Flags: []cli.Flag{&cli.BoolFlag{Name: "force", Usage: "stop even with agents running"}},
						Action: func(_ context.Context, cmd *cli.Command) error {
							return ui.StopVMs(cmd.Args().Slice(), cmd.Bool("force"))
						},
					},
				},
			},
			{Name: "status", Usage: "overview: UI, this host and every VM (running? builds? agents?)", Action: func(context.Context, *cli.Command) error {
				return ui.Status()
			}},
			{Name: "doctor", Usage: "check what's needed to run agents (host + VM, or this machine with --backend native)", Action: doctorAction},
			{Name: "setup", Usage: "install the pinned Syd engine (here, or in the VM)", Action: setupAction},
			{
				Name: "cmd", Usage: "(inside the sandbox) run or propose a host command: sydguard cmd --list",
				UsageText:       "sydguard cmd --list | NAME key=value... | --propose [--why TEXT] -- PROGRAM ARGS...",
				SkipFlagParsing: true,
				Action: func(_ context.Context, cmd *cli.Command) error {
					code, err := guest.RunClient(cmd.Args().Slice(), os.Stdin)
					if err != nil {
						fmt.Fprintln(os.Stderr, "sydguard:", err)
					}
					if code != 0 {
						return cli.Exit("", code)
					}
					return nil
				},
			},
			{Name: "overlay-mount", Hidden: true, Action: func(_ context.Context, cmd *cli.Command) error {
				pid, err := strconv.Atoi(cmd.Args().Get(0))
				if cmd.Args().Len() != 3 || err != nil || pid <= 0 {
					return errors.New("usage: sydguard overlay-mount PID SOURCE TARGET")
				}
				return guest.OverlayMount(pid, cmd.Args().Get(1), cmd.Args().Get(2))
			}},
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
			{Name: "daemon-stop", Hidden: true, Action: func(context.Context, *cli.Command) error {
				return guest.Call("POST", "/internal/quit", nil, nil)
			}},
			{Name: "engine-check", Hidden: true, Action: func(context.Context, *cli.Command) error {
				// Engine AND the network helper (it must match this build), so
				// a VM reinstalls the helper automatically after upgrades.
				if _, err := guest.FindEngine(); err != nil {
					return err
				}
				return guest.CheckNetworkHelper()
			}},
			{Name: "net-run", Hidden: true, Action: func(_ context.Context, cmd *cli.Command) error {
				args := cmd.Args().Slice()
				if len(args) < 2 {
					return fmt.Errorf("missing network command")
				}
				if args[1] == "--" {
					args = append(args[:1], args[2:]...)
				}
				return childExit(guest.NetworkRun(args[0], args[1:]))
			}},
			{Name: "net-owner", Hidden: true, Action: func(_ context.Context, cmd *cli.Command) error {
				args := cmd.Args().Slice()
				if len(args) < 2 {
					return fmt.Errorf("missing network command")
				}
				if args[1] == "--" {
					args = append(args[:1], args[2:]...)
				}
				return childExit(guest.NetworkOwner(args[0], args[1:]))
			}},
			{Name: "ipc-load", Hidden: true, Action: func(_ context.Context, cmd *cli.Command) error {
				return guest.IPCLoad(cmd.Args().Get(0), cmd.Args().Get(1))
			}},
			{Name: "ui-server", Hidden: true, Action: func(context.Context, *cli.Command) error { return ui.RunServer() }},
		},
	}
}

func childExit(err error) error {
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code := exit.ExitCode()
		if code < 0 {
			code = 1
		}
		return cli.Exit("", code)
	}
	return err
}

func landlockOverride(cmd *cli.Command) *bool {
	if !cmd.IsSet("landlock") {
		return nil
	}
	v := cmd.Bool("landlock")
	return &v
}

func limaOptions(cmd *cli.Command) lima.Options {
	return lima.Options{
		Backend: cmd.String("backend"), VM: cmd.String("vm"), LimaFile: cmd.String("lima"), Rules: cmd.String("rules"),
		Landlock: landlockOverride(cmd), Learn: cmd.Bool("learn"), LocalPorts: cmd.IntSlice("local-port"), PassEnv: cmd.StringSlice("pass-env"), Args: cmd.Args().Slice(),
	}
}

func runAction(_ context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() == 0 {
		return cli.ShowAppHelp(cmd)
	}
	useVM, err := lima.Use(limaOptions(cmd))
	if err != nil {
		return err
	}
	if useVM {
		return lima.Run(limaOptions(cmd))
	}
	code, err := guest.Run(guest.RunOptions{
		Landlock: landlockOverride(cmd), Rules: cmd.String("rules"), Learn: cmd.Bool("learn"),
		LocalPorts: cmd.IntSlice("local-port"), PassEnv: cmd.StringSlice("pass-env"), Args: cmd.Args().Slice(), OnReady: func() {
			if system.InLima() {
				return // the machine hosting the VM runs the UI
			}
			if started, err := ui.EnsureServer(); err != nil {
				fmt.Fprintln(os.Stderr, "sydguard: UI:", err)
			} else if started {
				ui.OpenBrowser(ui.URL())
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
	if system.InLima() {
		return errors.New("the UI runs on the machine hosting this VM: run `sydguard ui` there")
	}
	useVM, err := lima.Use(limaOptions(cmd.Root()))
	if err != nil {
		return err
	}
	if !useVM {
		if _, err := guest.EnsureDaemon(); err != nil {
			return err
		}
	}
	if _, err := ui.EnsureServer(); err != nil {
		return err
	}
	ui.OpenBrowser(ui.URL())
	fmt.Println(ui.URL())
	return nil
}

func doctorAction(_ context.Context, cmd *cli.Command) error {
	useVM, err := lima.Use(limaOptions(cmd.Root()))
	if err != nil {
		return err
	}
	if useVM {
		ui.UIStatus()
		ok, err := lima.Doctor(limaOptions(cmd.Root()))
		if err != nil {
			return err
		}
		if !ok {
			return cli.Exit("", 1)
		}
		return nil
	}
	if !guest.Doctor() {
		return cli.Exit("", 1)
	}
	return nil
}

func vmAction(_ context.Context, cmd *cli.Command) error {
	o := limaOptions(cmd.Root())
	useVM, err := lima.Use(o)
	if err != nil {
		return err
	}
	if !useVM {
		return errors.New("native backend selected; use --backend lima or --vm NAME for a VM shell")
	}
	return lima.Outside(o, cmd.Args().Slice())
}

func setupAction(_ context.Context, cmd *cli.Command) error {
	useVM, err := lima.Use(limaOptions(cmd.Root()))
	if err != nil {
		return err
	}
	if useVM {
		_, err := lima.Prepare(limaOptions(cmd.Root())) // installs the engine if missing
		return err
	}
	return guest.Setup()
}
