package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/Gobd/syd-guard/internal/backend"
	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/controller"
	"github.com/Gobd/syd-guard/internal/lima"
	"github.com/urfave/cli/v3"
)

func serveCommand() *cli.Command {
	return &cli.Command{Name: "serve", Hidden: true, Usage: "private Linux controller (automatically started by run)", Flags: []cli.Flag{&cli.StringFlag{Name: "state"}}, Action: func(parent context.Context, c *cli.Command) error {
		directory := c.String("state")
		if directory == "" {
			var err error
			directory, err = controller.StateDirectory()
			if err != nil {
				return err
			}
		}
		ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
		defer stop()
		return controller.Serve(ctx, directory)
	}}
}

func sessionsCommand() *cli.Command {
	return &cli.Command{Name: "sessions", Usage: "list tracked foreground supervisors (not descendant containment status)", Flags: []cli.Flag{
		&cli.StringFlag{Name: "backend", Value: "auto"}, &cli.StringFlag{Name: "vm", Value: "ai-sandbox"}, &cli.BoolFlag{Name: "history"}, &cli.BoolFlag{Name: "json"},
	}, Action: func(ctx context.Context, c *cli.Command) error {
		if c.Args().Len() != 0 {
			return cli.Exit("sessions does not take positional arguments", 2)
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
		if kind == backend.Lima {
			instance := settings.Lima.Instance
			if c.IsSet("vm") {
				instance = c.String("vm")
			}
			guest := []string{"sydguard", "sessions", "--backend", "native"}
			if c.Bool("history") {
				guest = append(guest, "--history")
			}
			if c.Bool("json") {
				guest = append(guest, "--json")
			}
			argv, err := lima.ShellArgs(instance, guest)
			if err != nil {
				return err
			}
			command := exec.CommandContext(ctx, "limactl", argv...) //nolint:gosec // validated instance and direct fixed guest argv
			command.Stdout, command.Stderr = c.Writer, c.ErrWriter
			return command.Run()
		}
		directory, err := controller.StateDirectory()
		if err != nil {
			return err
		}
		client, err := controller.OpenClient(directory)
		if err != nil {
			return err
		}
		defer client.Close()
		values, err := client.Sessions(ctx, c.Bool("history"))
		if err != nil {
			return err
		}
		if c.Bool("json") {
			return json.NewEncoder(c.Writer).Encode(values)
		}
		for _, value := range values {
			if _, err := fmt.Fprintf(c.Writer, "%s\t%s\t%s\t%s\n", value.ID, value.Name, value.State, value.Project); err != nil {
				return err
			}
		}
		return nil
	}}
}
