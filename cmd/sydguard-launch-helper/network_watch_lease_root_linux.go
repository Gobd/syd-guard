//go:build linux

package main

import (
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
)

// This is evaluated only against a pidfd/start/executable-pinned internal peer;
// a socketpair's creator credentials do not identify its post-exec child.
func verifyNetworkLeaseRootCredentials(pid int) error {
	if pid <= 0 {
		return errors.New("invalid lease peer")
	}
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(data) > 16384 {
		return errors.New("lease peer status unavailable")
	}
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		v := strings.Fields(line)
		if len(v) > 0 && v[0] == "Uid:" {
			if found || len(v) != 5 || v[1] != "0" || v[2] != "0" || v[3] != "0" || v[4] != "0" {
				return errors.New("lease peer is not root")
			}
			found = true
		}
	}
	if !found {
		return errors.New("missing lease peer credentials")
	}
	return nil
}
func verifyNetworkLeaseChild(child *networkChild) error {
	if err := child.verify(); err != nil {
		return err
	}
	if err := verifyPidfdPID(child.pidfd, child.pid); err != nil {
		return err
	}
	if err := verifyNetworkLeaseRootCredentials(child.pid); err != nil {
		return err
	}
	return child.verify()
}
