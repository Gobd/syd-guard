//go:build !linux

package main

import "fmt"

func managedPlatform() error                          { return fmt.Errorf("managed intent requires Linux VM-local storage") }
func createManagedCredential(string) error            { return managedPlatform() }
func openManagedClient(string) (managedClient, error) { return nil, managedPlatform() }
