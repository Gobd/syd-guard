//go:build !linux

package main

import (
	"context"
	"fmt"
	"io"

	"github.com/Gobd/syd-guard/internal/managedlaunch"
)

func managedPlatform() error                          { return fmt.Errorf("managed intent requires Linux VM-local storage") }
func createManagedCredential(string) error            { return managedPlatform() }
func openManagedClient(string) (managedClient, error) { return nil, managedPlatform() }
func launchManagedHelper(context.Context, string, managedlaunch.Request, io.Writer, io.Writer) error {
	return managedPlatform()
}
