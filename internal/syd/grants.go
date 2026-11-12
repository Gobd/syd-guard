package syd

import (
	"context"
	"fmt"
	"path/filepath"
)

var fileCapabilities = map[string]string{"read": "read,stat", "stat": "stat", "write": "write,stat", "create": "create,stat", "delete": "delete,stat", "rename": "rename,stat", "truncate": "truncate,stat", "mkdir": "mkdir,stat", "rmdir": "rmdir,stat", "readdir": "readdir,stat", "readlink": "readlink,stat", "chdir": "chdir,stat"}

func FileCapability(capability string) bool { _, ok := fileCapabilities[capability]; return ok }

// GrantPath grants one exact path, never a recursive glob or raw Syd command.
// The controller must first verify immutable ceilings and protected path overlap.
func (client IPC) GrantPath(ctx context.Context, capability, path string) error {
	caps, ok := fileCapabilities[capability]
	if !ok {
		return fmt.Errorf("unsupported filesystem capability")
	}
	if err := literalPath(path); err != nil {
		return err
	}
	if filepath.Clean(path) != path {
		return fmt.Errorf("grant path must be canonical")
	}
	var ack struct {
		Err     int    `json:"err"`
		Message string `json:"msg"`
	}
	if err := client.exchange(ctx, "allow/"+caps+"+"+path, &ack); err != nil {
		return err
	}
	if ack.Err != 0 || ack.Message != "ACK" {
		return fmt.Errorf("syd rejected exact file grant: %d %s", ack.Err, ack.Message)
	}
	return nil
}

func LearningRules(scopes []string, socket string) (string, []string, error) {
	if err := literalPath(socket); err != nil {
		return "", nil, err
	}
	var rules string
	canonical := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		root, err := canonicalDirectory(scope)
		if err != nil {
			return "", nil, err
		}
		// Reuse the baseline's broad-workspace guard, but don't adopt its path grants.
		if _, err := Profile(root, root, nil); err != nil {
			return "", nil, err
		}
		rules += "allow/lock/read,readdir,write,create,delete,rename,truncate,mkdir,rmdir,symlink,exec+" + root + "\n"
		canonical = append(canonical, root)
	}
	if len(canonical) == 0 {
		return "", nil, fmt.Errorf("learning requires at least one explicit filesystem ceiling (--scope)")
	}
	rules += "ipc:" + socket + "\nlock:ipc\n"
	return rules, canonical, nil
}
