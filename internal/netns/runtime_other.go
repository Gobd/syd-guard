//go:build !linux

package netns

import (
	"context"
	"fmt"
)

var errUnavailable = fmt.Errorf("network namespace lifecycle requires Linux")

// Runtime is unavailable outside Linux.
type Runtime struct{ Topology Topology }

func Create(context.Context, Topology, uint16, uint16, string) (*Runtime, error) {
	return nil, fmt.Errorf("network namespace lifecycle requires Linux")
}
func (*Runtime) Close() error { return errUnavailable }
func (*Runtime) UserExec(int, int, []string) (Command, error) {
	return Command{}, fmt.Errorf("network namespace lifecycle requires Linux")
}
