//go:build linux

package controller

import (
	"context"
	"errors"
	"net"

	"github.com/Gobd/syd-guard/internal/managedlive"
)

type managedLiveDial func(context.Context) (*net.UnixConn, error)

func exchangeManagedLive(ctx context.Context, dial managedLiveDial, request any) (any, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, errors.New("live deadline required")
	}
	conn, err := dial(ctx)
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("missing live connection")
	}
	defer conn.Close()
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = conn.Close(); close(closed) })
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return managedlive.Exchange(conn, request, deadline)
}
