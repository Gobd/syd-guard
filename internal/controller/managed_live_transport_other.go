//go:build !linux

package controller

import (
	"context"
	"errors"
	"net"
)

type managedLiveDial func(context.Context) (*net.UnixConn, error)

func exchangeManagedLive(context.Context, managedLiveDial, any) (any, error) {
	return nil, errors.New("managed live transport requires Linux")
}
