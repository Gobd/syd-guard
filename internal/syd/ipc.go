package syd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"
)

// IPC is a typed operator-side adapter. The workload must not reach its socket;
// matching Unix peer UID alone does not distinguish operator from agent.
type IPC struct{ Socket string }

type APIVersion struct {
	Major   int    `json:"major"`
	Minor   int    `json:"minor"`
	Version string `json:"version"`
}

func (client IPC) Version(ctx context.Context) (APIVersion, error) {
	var version APIVersion
	if err := client.exchange(ctx, "version", &version); err != nil {
		return version, err
	}
	if version.Major != 3 || version.Minor != 2 || version.Version != "3.2" {
		return version, fmt.Errorf("unsupported Syd IPC API %s", version.Version)
	}
	return version, nil
}

// GrantReadDirectory permits only path-level read/metadata operations. The
// caller must authorize the target and arrange a predeclared Landlock ceiling;
// this cannot widen an immutable kernel ruleset. It does not grant write/delete.
func (client IPC) GrantReadDirectory(ctx context.Context, path string) error {
	path, err := canonicalDirectory(path)
	if err != nil {
		return err
	}
	for _, target := range []string{path, path + "/***"} {
		var ack struct {
			Err     int    `json:"err"`
			Message string `json:"msg"`
		}
		if err := client.exchange(ctx, "allow/read,stat,readdir,readlink,chdir+"+target, &ack); err != nil {
			return err
		}
		if ack.Err != 0 || ack.Message != "ACK" {
			return fmt.Errorf("syd rejected read grant: errno=%d message=%s", ack.Err, ack.Message)
		}
	}
	return nil
}

func (client IPC) exchange(ctx context.Context, command string, response any) error {
	if err := literalPath(client.Socket); err != nil {
		return err
	}
	connection, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", client.Socket)
	if err != nil {
		return fmt.Errorf("connect Syd IPC: %w", err)
	}
	defer func() { _ = connection.Close() }()
	deadline := time.Now().Add(3 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return err
	}
	if _, err := io.WriteString(connection, command+"\n"); err != nil {
		return err
	}
	if err := json.NewDecoder(io.LimitReader(connection, 64*1024)).Decode(response); err != nil {
		return fmt.Errorf("decode bounded Syd IPC response: %w", err)
	}
	return nil
}
