//go:build linux

package main

import (
	"context"
	"io"

	"github.com/Gobd/syd-guard/internal/managedlaunch"
	"github.com/Gobd/syd-guard/internal/managedstore"
)

func managedPlatform() error                               { return nil }
func createManagedCredential(path string) error            { return managedstore.CreateCredential(path) }
func openManagedClient(path string) (managedClient, error) { return managedstore.NewClient(path) }

func launchManagedHelper(ctx context.Context, credential string, request managedlaunch.Request, stdout, stderr io.Writer) error {
	client, err := managedstore.NewClient(credential)
	if err != nil {
		return err
	}
	return client.Launch(ctx, request, stdout, stderr)
}
