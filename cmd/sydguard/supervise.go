package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Gobd/syd-guard/internal/controller"
	"github.com/Gobd/syd-guard/internal/files"
	"github.com/Gobd/syd-guard/internal/syd"
	"github.com/urfave/cli/v3"
)

// supervisorSpec is private launcher-to-supervisor state, never a workload argument.
type supervisorSpec struct {
	Engine, Directory, State, SessionID, TransitDNS, Gateway string
	Args, Scopes, Environment, ReadInputs, ExecInputs        []string
}

func supervisorCommand() *cli.Command {
	return &cli.Command{Name: "supervise", Hidden: true, Action: func(ctx context.Context, c *cli.Command) error {
		if c.Args().Len() != 1 || os.Geteuid() == 0 {
			return fmt.Errorf("invalid supervisor invocation")
		}
		path := c.Args().First()
		dir := filepath.Dir(path)
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "spec.json" || !strings.HasPrefix(filepath.Base(dir), "run-") || filepath.Base(filepath.Dir(dir)) != "runs" {
			return fmt.Errorf("invalid supervisor authority")
		}
		for _, p := range []string{filepath.Dir(dir), dir, path} {
			info, err := os.Lstat(p)
			if err != nil {
				return err
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || int(stat.Uid) != os.Geteuid() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
				return fmt.Errorf("unsafe supervisor authority")
			}
			if p == path {
				if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Nlink != 1 || info.Size() > 1024*1024 {
					return fmt.Errorf("invalid supervisor specification")
				}
			} else if !info.IsDir() || info.Mode().Perm() != 0o700 {
				return fmt.Errorf("invalid supervisor directory")
			}
		}
		data, err := os.ReadFile(path) //nolint:gosec // validated private run authority and fixed spec basename
		if err != nil {
			return err
		}
		var spec supervisorSpec
		if err = json.Unmarshal(data, &spec); err != nil {
			return err
		}
		if spec.State != filepath.Dir(filepath.Dir(dir)) {
			return fmt.Errorf("supervisor state mismatch")
		}
		client, err := controller.OpenClient(spec.State)
		if err != nil {
			return err
		}
		defer client.Close()
		os.Clearenv()
		for _, entry := range spec.Environment {
			name, value, ok := strings.Cut(entry, "=")
			if ok && name != "SYD_LOG_FD" {
				if err = os.Setenv(name, value); err != nil {
					return err
				}
			}
		}
		options := syd.RunOptions{Engine: spec.Engine, Directory: spec.Directory, Args: spec.Args, Scopes: spec.Scopes, ReadInputs: spec.ReadInputs, ExecInputs: spec.ExecInputs, TransitDNS: spec.TransitDNS, Gateway: spec.Gateway, Stdin: os.Stdin, Stdout: c.Writer, Stderr: c.ErrWriter}
		options.OnReady = func(socket string, scopes, protected []string) error {
			return client.FileReady(ctx, spec.SessionID, files.Context{Socket: socket, Scopes: scopes, Protected: protected})
		}
		if spec.TransitDNS != "" {
			options.OnNetworkReady = func(socket string) error { return client.NetworkReady(ctx, spec.SessionID, socket) }
		}
		options.OnEvent = func(data []byte) error {
			eventCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			if _, ok := syd.ParseSyntheticConnectDenial(data); ok && spec.TransitDNS != "" {
				if err := client.NetworkEvent(eventCtx, spec.SessionID, controller.NetworkEvent{Record: data}); err != nil {
					return err
				}
			}
			for _, event := range files.ParseEvents(data) {
				if syd.FileCapability(event.Capability) {
					if err := client.FileEvent(eventCtx, spec.SessionID, event); err != nil {
						return err
					}
				}
			}
			return nil
		}
		ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()
		code, err := syd.Run(ctx, options)
		if err != nil {
			return err
		}
		if code != 0 {
			return cli.Exit("", code)
		}
		return nil
	}}
}
