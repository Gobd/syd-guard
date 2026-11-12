package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/Gobd/syd-guard/internal/config"
	"github.com/urfave/cli/v3"
)

func configCommand() *cli.Command {
	return &cli.Command{Name: "config", Usage: "inspect/edit private operator defaults (never restarts a VM)", Commands: []*cli.Command{
		{Name: "path", Usage: "print operator config location", Action: func(_ context.Context, c *cli.Command) error {
			path, err := config.Path()
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(c.Writer, path)
			return err
		}},
		{Name: "show", Usage: "print effective operator settings", Action: func(_ context.Context, c *cli.Command) error {
			settings, err := config.Load()
			if err != nil {
				return err
			}
			encoder := json.NewEncoder(c.Writer)
			encoder.SetIndent("", "  ")
			return encoder.Encode(settings)
		}},
		{Name: "lima", Usage: "default Lima recipe; choosing it does not apply it to a VM", Commands: []*cli.Command{
			{Name: "path", Usage: "print selected recipe path", Action: func(_ context.Context, c *cli.Command) error {
				settings, err := config.Load()
				if err != nil {
					return err
				}
				_, err = fmt.Fprintln(c.Writer, settings.Lima.ConfigPath)
				return err
			}},
			{Name: "show", Usage: "print selected recipe text and report fingerprint drift", Action: func(_ context.Context, c *cli.Command) error {
				settings, err := config.Load()
				if err != nil {
					return err
				}
				path, hash, err := config.ResolveRecipe(settings.Lima.ConfigPath)
				if err != nil {
					return err
				}
				if settings.Lima.ConfigSHA256 == "" {
					_, _ = fmt.Fprintln(c.ErrWriter, "Recipe is not yet fingerprinted; use config lima set before future VM creation.")
				} else if settings.Lima.ConfigSHA256 != hash {
					_, _ = fmt.Fprintln(c.ErrWriter, "Recipe changed since selection; no VM changes applied.")
				}
				data, err := os.ReadFile(path) //nolint:gosec // canonical regular recipe explicitly selected by the operator
				if err != nil {
					return err
				}
				_, err = c.Writer.Write(data)
				return err
			}},
			{Name: "set", Usage: "select an existing recipe and record its current file hash", ArgsUsage: "FILE", Action: func(_ context.Context, c *cli.Command) error {
				if c.Args().Len() != 1 {
					return cli.Exit("usage: sydguard config lima set FILE", 2)
				}
				return setRecipe(c, c.Args().First())
			}},
			{Name: "edit", Usage: "open the selected existing recipe using VISUAL/EDITOR", Action: editRecipe},
		}},
	}}
}

func setRecipe(c *cli.Command, path string) error {
	settings, err := config.Load()
	if err != nil {
		return err
	}
	path, hash, err := config.ResolveRecipe(path)
	if err != nil {
		return err
	}
	settings.Lima.ConfigPath, settings.Lima.ConfigSHA256 = path, hash
	if err := config.Save(settings); err != nil {
		return err
	}
	_, err = fmt.Fprintf(c.Writer, "Default Lima recipe: %s\nFile SHA256: %s\nNo VM was created, restarted or changed.\n", path, hash)
	return err
}

func editRecipe(ctx context.Context, c *cli.Command) error {
	if c.Args().Len() != 0 {
		return cli.Exit("config lima edit does not take positional arguments", 2)
	}
	settings, err := config.Load()
	if err != nil {
		return err
	}
	path, _, err := config.ResolveRecipe(settings.Lima.ConfigPath)
	if err != nil {
		return fmt.Errorf("selected recipe is unavailable; use config lima set FILE: %w", err)
	}
	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		editor = "vi"
	}
	// Simple argv, not shell evaluation. Quoted executable paths are deliberately
	// unsupported rather than evaluating arbitrary editor shell expressions.
	argv := strings.Fields(editor)
	if len(argv) == 0 {
		return fmt.Errorf("empty editor command")
	}
	command := exec.CommandContext(ctx, argv[0], append(argv[1:], path)...) //nolint:gosec // operator-selected editor argv, intentionally no shell evaluation
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, c.Writer, c.ErrWriter
	if err := command.Run(); err != nil {
		return err
	}
	return setRecipe(c, path)
}
