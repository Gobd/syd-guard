//go:build linux

package main

import (
	"encoding/hex"
	"errors"
	"time"

	"github.com/Gobd/syd-guard/internal/managedlive"
)

// liveWatchDeadline is owned by the watchdog, not the serving parent. An ARM
// ACK must be sent only after arm succeeds. Polling must use deadline directly;
// liveness traffic and status cannot renew it. This source primitive is not
// yet connected to the existing one-shot watchdog protocol.
type liveWatchDeadline struct {
	request  string
	sequence uint64
	deadline time.Time
}

func validWatchRequest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func (w *liveWatchDeadline) arm(request string, sequence uint64, startup bool, now time.Time) error {
	if w.request != "" || !validWatchRequest(request) || sequence == 0 || now.IsZero() {
		return errors.New("invalid or busy watchdog arm")
	}
	duration := managedlive.UpdateTimeout
	if startup {
		if sequence != 1 {
			return errors.New("invalid startup sequence")
		}
		duration = managedlive.StartupTimeout
	}
	w.request = request
	w.sequence = sequence
	w.deadline = now.Add(duration)
	return nil
}
func (w *liveWatchDeadline) complete(request string, sequence uint64, now time.Time) error {
	if w.request == "" || request != w.request || sequence != w.sequence || !now.Before(w.deadline) {
		return errors.New("invalid or expired watchdog completion; fail-stop")
	}
	*w = liveWatchDeadline{}
	return nil
}
func (w *liveWatchDeadline) expired(now time.Time) bool {
	return w.request != "" && !now.Before(w.deadline)
}
