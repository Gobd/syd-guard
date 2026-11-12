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
	"runtime"
	"syscall"
	"time"

	"github.com/Gobd/syd-guard/internal/backend"
	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/controller"
	"github.com/Gobd/syd-guard/internal/lima"
	"github.com/Gobd/syd-guard/internal/webui"
	"github.com/urfave/cli/v3"
)

func apiCommand() *cli.Command {
	return &cli.Command{Name: "operator-api", Hidden: true, Flags: []cli.Flag{&cli.StringFlag{Name: "method", Value: "GET"}, &cli.StringFlag{Name: "path"}}, Action: func(ctx context.Context, c *cli.Command) error {
		state, err := controller.StateDirectory()
		if err != nil {
			return err
		}
		client, err := controller.OpenClient(state)
		if err != nil {
			return err
		}
		defer client.Close()
		var input any
		if c.String("method") == "POST" || c.String("method") == "PUT" {
			data, err := io.ReadAll(io.LimitReader(os.Stdin, 1024*1024+4097))
			if err != nil {
				return err
			}
			if len(data) > 1024*1024+4096 || !json.Valid(data) {
				return fmt.Errorf("invalid bounded operator JSON")
			}
			input = json.RawMessage(data)
		}
		data, err := client.Operate(ctx, c.String("method"), c.String("path"), input)
		var detail *controller.OperatorError
		if err != nil && !errors.As(err, &detail) {
			return err
		}
		return json.NewEncoder(c.Writer).Encode(operatorResponse{Data: data, Error: detail})
	}}
}

type operatorResponse struct {
	Data  json.RawMessage           `json:"data,omitempty"`
	Error *controller.OperatorError `json:"error,omitempty"`
}

func uiCommand() *cli.Command {
	return &cli.Command{Name: "ui", Usage: "operator-only approvals bridge; use --detach, status, restart or stop", Flags: []cli.Flag{
		&cli.StringFlag{Name: "backend", Value: "auto"}, &cli.StringFlag{Name: "vm", Value: "ai-sandbox"},
		&cli.StringFlag{Name: "guest-sydguard", Usage: "absolute guest CLI path for Lima delegation"},
		&cli.StringFlag{Name: "guest-config-home", Usage: "absolute guest XDG_CONFIG_HOME for Lima delegation"},
		&cli.BoolFlag{Name: "detach"}, &cli.BoolFlag{Name: "managed-child", Hidden: true},
	}, Action: uiAction}
}

func uiAction(parent context.Context, c *cli.Command) error {
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
	instance := ""
	if kind == backend.Lima {
		instance = settings.Lima.Instance
		if c.IsSet("vm") {
			instance = c.String("vm")
		}
		if _, err := lima.ShellArgs(instance, []string{"true"}); err != nil {
			return err
		}
	}
	guestExecutable, guestConfigHome := c.String("guest-sydguard"), c.String("guest-config-home")
	if kind == backend.Lima {
		if _, err := lima.GuestCommand(guestExecutable, guestConfigHome, nil); err != nil {
			return err
		}
	} else if guestExecutable != "" || guestConfigHome != "" {
		return fmt.Errorf("guest adapter flags require Lima")
	}
	identity := string(kind)
	if instance != "" {
		identity += ":" + instance + "\x00" + guestExecutable + "\x00" + guestConfigHome
	}
	manager, err := newUIManager(identity)
	if err != nil {
		return err
	}
	manager.guestExecutable, manager.guestConfigHome = guestExecutable, guestConfigHome
	if c.Args().Len() > 1 {
		return fmt.Errorf("ui accepts only status, restart or stop")
	}
	action := c.Args().First()
	if action != "" && action != "status" && action != "restart" && action != "stop" {
		return fmt.Errorf("unknown ui action %q", action)
	}
	if c.Bool("managed-child") {
		if action != "" || c.Bool("detach") {
			return fmt.Errorf("invalid managed child arguments")
		}
		return runUIBridge(parent, manager, kind, instance, c.Writer, c.ErrWriter, false, nil)
	}
	if c.Bool("detach") && action != "" {
		return fmt.Errorf("--detach cannot be combined with ui %s", action)
	}
	return manager.command(parent, action, c.Bool("detach"), kind, instance, c.Writer, c.ErrWriter)
}

func runUIBridge(parent context.Context, manager *uiManager, kind backend.Kind, instance string, out, stderr io.Writer, foreground bool, ready func()) error {
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()
	return manager.serve(ctx, out, foreground, ready, func(ctx context.Context) (webui.Operator, func(), error) {
		if kind == backend.Lima {
			return func(ctx context.Context, method, path string, data []byte) ([]byte, error) {
				guest, err := lima.GuestCommand(manager.guestExecutable, manager.guestConfigHome, []string{"operator-api", "--method", method, "--path", path})
				if err != nil {
					return nil, err
				}
				argv, err := lima.ShellArgs(instance, guest)
				if err != nil {
					return nil, err
				}
				command := exec.CommandContext(ctx, "limactl", argv...) //nolint:gosec // validated instance and direct argv
				command.WaitDelay = 2 * time.Second
				command.Stdin, command.Stderr = bytes.NewReader(data), stderr
				output, err := command.Output()
				if err != nil {
					return nil, err
				}
				var response operatorResponse
				if err := json.Unmarshal(output, &response); err != nil {
					return nil, fmt.Errorf("invalid guest operator response")
				}
				if response.Error != nil {
					return nil, response.Error
				}
				if !json.Valid(response.Data) {
					return nil, fmt.Errorf("invalid guest operator data")
				}
				return response.Data, nil
			}, func() {}, nil
		}
		state, err := controller.StateDirectory()
		if err != nil {
			return nil, nil, err
		}
		client, err := controller.OpenClient(state)
		if err != nil {
			return nil, nil, err
		}
		executable, err := os.Executable()
		if err != nil {
			client.Close()
			return nil, nil, err
		}
		if err := client.Ensure(ctx, executable); err != nil {
			client.Close()
			return nil, nil, err
		}
		return func(ctx context.Context, method, path string, data []byte) ([]byte, error) {
			var input any
			if method == "POST" || method == "PUT" {
				if !json.Valid(data) {
					return nil, fmt.Errorf("invalid JSON")
				}
				input = json.RawMessage(data)
			}
			return client.Operate(ctx, method, path, input)
		}, func() { client.Close() }, nil
	})
}
