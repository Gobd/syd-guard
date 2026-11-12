package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Gobd/syd-guard/internal/config"
	"github.com/Gobd/syd-guard/internal/controller"
	"github.com/Gobd/syd-guard/internal/managedstore"
	"github.com/urfave/cli/v3"
)

var (
	managedOpen             = openManagedClient
	managedCheckPlatform    = managedPlatform
	managedCreateCredential = createManagedCredential
)

type managedClient interface {
	controller.ManagedProfileCatalogClient
	Register(context.Context, string) (string, error)
	Create(context.Context, string, string) (managedstore.Response, error)
}

func managedCommand() *cli.Command {
	flags := []cli.Flag{&cli.BoolFlag{Name: "experimental", Usage: "explicitly opt in to experimental VM-local managed intent"}}
	refFlags := func() []cli.Flag {
		return []cli.Flag{&cli.StringFlag{Name: "project-id", Required: true}, &cli.StringFlag{Name: "name", Value: "default"}}
	}
	withConfirm := func(f []cli.Flag) []cli.Flag {
		return append(f, &cli.BoolFlag{Name: "yes", Usage: "confirm this managed mutation"})
	}
	return &cli.Command{Name: "managed", Usage: "experimental helper-authoritative intent (not launch permissions)", Flags: flags, Commands: []*cli.Command{
		{Name: "credential-init", Usage: "create a private credential for separate administrator enrollment", Action: func(_ context.Context, c *cli.Command) error {
			state, err := managedState(c)
			if err != nil {
				return err
			}
			if err := managedCreateCredential(managedCredentialPath(state)); err != nil {
				return err
			}
			_, err = fmt.Fprintln(c.Writer, managedCredentialPath(state))
			return err
		}},
		{Name: "register", Usage: "register a fresh VM-local project; never adopts existing policy", Flags: withConfirm([]cli.Flag{&cli.StringFlag{Name: "directory", Required: true}}), Action: func(ctx context.Context, c *cli.Command) error {
			client, err := managedClientFor(c, true)
			if err != nil {
				return err
			}
			state, err := controller.StateDirectory()
			if err != nil {
				return err
			}
			project := c.String("directory")
			if err := managedstore.ValidateProjectPath(project); err != nil {
				return err
			}
			canonical, err := filepath.EvalSymlinks(project)
			if err != nil || canonical != project || pathsOverlap(project, state) {
				return fmt.Errorf("project must be canonical and disjoint from controller authority")
			}
			id, err := client.Register(ctx, project)
			if err != nil {
				return err
			}
			err = managedOutput(func() error {
				_, err := fmt.Fprintln(c.Writer, id)
				return err
			})
			if err != nil {
				return fmt.Errorf("%w: registration committed but result output failed; administrator inspection required before retry: %w", managedstore.ErrIndeterminate, err)
			}
			return nil
		}},
		{Name: "create", Usage: "create an empty managed profile by registration ID", Flags: withConfirm(refFlags()), Action: func(ctx context.Context, c *cli.Command) error {
			client, err := managedClientFor(c, true)
			if err != nil {
				return err
			}
			response, err := client.Create(ctx, c.String("project-id"), c.String("name"))
			if err != nil {
				return err
			}
			return managedSnapshot(c, response, true)
		}},
		{Name: "catalog", Usage: "list authenticated registered profiles", Action: func(ctx context.Context, c *cli.Command) error {
			client, err := managedClientFor(c, false)
			if err != nil {
				return err
			}
			entries, err := client.Catalog(ctx)
			if err != nil {
				return err
			}
			return json.NewEncoder(c.Writer).Encode(entries)
		}},
		{Name: "show", Usage: "read authenticated managed intent and revision", Flags: refFlags(), Action: func(ctx context.Context, c *cli.Command) error {
			client, err := managedClientFor(c, false)
			if err != nil {
				return err
			}
			response, err := client.Read(ctx, c.String("project-id"), c.String("name"))
			if err != nil {
				return err
			}
			return managedSnapshot(c, response, false)
		}},
		{Name: "review", Usage: "record explicit review of an authenticated exact revision", Flags: withConfirm(append(refFlags(), &cli.StringFlag{Name: "expected-revision", Required: true})), Action: func(ctx context.Context, c *cli.Command) error {
			client, err := managedClientFor(c, true)
			if err != nil {
				return err
			}
			response, err := client.Read(ctx, c.String("project-id"), c.String("name"))
			if err != nil {
				return err
			}
			if response.Project != c.String("project-id") || response.Name != c.String("name") || response.Namespace == nil {
				return fmt.Errorf("authenticated review selection mismatch")
			}
			if response.Revision != c.String("expected-revision") {
				return managedstore.ErrConflict
			}
			if _, err := reviewRecord(response); err != nil {
				return err
			}
			if err := managedSnapshot(c, response, false); err != nil {
				return err
			}
			state, err := controller.StateDirectory()
			if err != nil {
				return err
			}
			return saveManagedReview(state, response)
		}},
		{Name: "save", Usage: "CAS replace intent from stdin; does not change running permissions", Flags: withConfirm(append(refFlags(), &cli.StringFlag{Name: "expected-revision", Required: true})), Action: func(ctx context.Context, c *cli.Command) error {
			client, err := managedClientFor(c, true)
			if err != nil {
				return err
			}
			data, err := io.ReadAll(io.LimitReader(c.Reader, managedstore.Limit+1))
			if err != nil {
				return err
			}
			if len(data) > managedstore.Limit {
				return fmt.Errorf("profile too large")
			}
			response, err := client.Replace(ctx, c.String("project-id"), c.String("name"), c.String("expected-revision"), data)
			if err != nil {
				return err
			}
			return managedSnapshot(c, response, true)
		}},
		{Name: "controller", Usage: "run a private candidate controller in foreground after authenticated catalog", Flags: []cli.Flag{&cli.BoolFlag{Name: "edit", Usage: "explicitly enable managed intent editing; never applies permissions"}}, Action: func(parent context.Context, c *cli.Command) error {
			client, err := managedClientFor(c, false)
			if err != nil {
				return err
			}
			state, err := controller.StateDirectory()
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
			defer stop()
			return controller.ServeManaged(ctx, state, func(ctx context.Context) (controller.ProfileProvider, error) {
				return controller.NewCatalogProfileProvider(ctx, client, c.Bool("edit"))
			})
		}},
	}}
}

func managedState(c *cli.Command) (string, error) {
	if !c.Bool("experimental") {
		return "", fmt.Errorf("managed intent requires --experimental")
	}
	if c.Args().Len() != 0 {
		return "", fmt.Errorf("managed commands do not accept positional arguments")
	}
	if err := managedCheckPlatform(); err != nil {
		return "", err
	}
	state, err := controller.StateDirectory()
	if err != nil {
		return "", err
	}
	if err := controller.PrepareState(state); err != nil {
		return "", err
	}
	if err := controller.PrepareState(filepath.Join(state, config.PrivateAuthorityFolder)); err != nil {
		return "", err
	}
	return state, nil
}

func managedCredentialPath(state string) string {
	return filepath.Join(state, config.PrivateAuthorityFolder, "managed-credential")
}

func managedClientFor(c *cli.Command, mutate bool) (managedClient, error) {
	if mutate && !c.Bool("yes") {
		return nil, fmt.Errorf("managed mutation requires --yes")
	}
	state, err := managedState(c)
	if err != nil {
		return nil, err
	}
	return managedOpen(managedCredentialPath(state))
}

func pathsOverlap(a, b string) bool {
	contains := func(parent, child string) bool {
		rel, err := filepath.Rel(parent, child)
		return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
	}
	return contains(a, b) || contains(b, a)
}

// Go otherwise terminates on a broken fd-1 pipe before returning EPIPE. Scope
// SIGPIPE notification to these managed result writes; workload semantics and
// normal foreground commands retain their existing behavior.
func managedOutput(write func() error) error {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGPIPE)
	defer signal.Stop(ch)
	return write()
}

func managedSnapshot(c *cli.Command, r managedstore.Response, mutation bool) error {
	err := managedOutput(func() error {
		return json.NewEncoder(c.Writer).Encode(struct {
			Project   string                         `json:"project"`
			Name      string                         `json:"name"`
			Revision  string                         `json:"revision"`
			Namespace *managedstore.ProjectNamespace `json:"namespace"`
			Profile   json.RawMessage                `json:"profile"`
		}{r.Project, r.Name, r.Revision, r.Namespace, r.Profile})
	})
	if err != nil && mutation {
		return fmt.Errorf("%w: mutation committed but result output failed; authenticate a fresh snapshot before retry: %w", managedstore.ErrIndeterminate, err)
	}
	return err
}
