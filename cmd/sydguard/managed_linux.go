//go:build linux

package main

import "github.com/Gobd/syd-guard/internal/managedstore"

func managedPlatform() error                               { return nil }
func createManagedCredential(path string) error            { return managedstore.CreateCredential(path) }
func openManagedClient(path string) (managedClient, error) { return managedstore.NewClient(path) }
