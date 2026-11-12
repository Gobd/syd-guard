package main

import (
	"context"

	"github.com/urfave/cli/v3"
)

func learnCommand() *cli.Command {
	command := runCommand()
	command.Name = "learn"
	command.Usage = "permissive discovery recording (not yet available)"
	command.Action = func(context.Context, *cli.Command) error {
		return cli.Exit("learn discovery recording is not yet available: trusted successful-access capture and secret/authority ceilings are unverified; use run for reviewed live approvals", 1)
	}
	return command
}
