package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Gobd/syd-guard/internal/config"
	"github.com/urfave/cli/v3"
)

func profileCommand() *cli.Command {
	selectProfile := func(c *cli.Command, create bool) (config.SelectedProfile, error) {
		return config.SelectProfile(c.String("directory"), c.String("name"), create)
	}
	return &cli.Command{Name: "profile", Usage: "named, readable project configs; discovered grants require explicit operator trust", Flags: []cli.Flag{&cli.StringFlag{Name: "directory", Value: "."}, &cli.StringFlag{Name: "name", Value: "default"}}, Commands: []*cli.Command{
		{Name: "create", Usage: "create an empty named config in the nearest project folder", Action: func(_ context.Context, c *cli.Command) error {
			profile, err := selectProfile(c, true)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(c.Writer, profile.Path)
			return err
		}},
		{Name: "path", Usage: "show discovered config path", Action: func(_ context.Context, c *cli.Command) error {
			profile, err := selectProfile(c, false)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(c.Writer, profile.Path)
			return err
		}},
		{Name: "show", Usage: "show config and review status", Action: func(_ context.Context, c *cli.Command) error {
			profile, err := selectProfile(c, false)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintf(c.ErrWriter, "Config: %s\nReviewed content: %t\n", profile.Path, profile.Trusted)
			encoder := json.NewEncoder(c.Writer)
			encoder.SetIndent("", "  ")
			return encoder.Encode(profile.Profile)
		}},
		{Name: "trust", Usage: "explicitly review and trust current contents", Flags: []cli.Flag{&cli.BoolFlag{Name: "yes", Usage: "confirm you reviewed the printed permissions"}}, Action: func(_ context.Context, c *cli.Command) error {
			profile, err := selectProfile(c, false)
			if err != nil {
				return err
			}
			encoder := json.NewEncoder(c.Writer)
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(profile.Profile); err != nil {
				return err
			}
			if !c.Bool("yes") {
				return cli.Exit("Review these permissions, then repeat with --yes. Nothing was trusted.", 2)
			}
			return config.TrustProfile(profile)
		}},
	}}
}
