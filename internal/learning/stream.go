package learning

import (
	"errors"
	"io"
	"sync"
)

// Stream drains a dedicated trusted log reader concurrently with the workload.
// It must not be fed by an untrusted logger or an OnEvent callback.
type Stream struct {
	collector *Collector
	done      chan error
	once      sync.Once
	err       error
}

// StartStream must be called once per collector before starting the workload.
// The caller owns and closes the writer, including on launch failure.
func StartStream(c *Collector, reader io.Reader) (*Stream, error) {
	if c == nil || reader == nil {
		return nil, errors.New("collector and trusted reader required")
	}
	s := &Stream{collector: c, done: make(chan error, 1)}
	go func() { s.done <- c.Drain(reader) }()
	return s, nil
}

// Finish closes the gateway/session and waits for every in-flight public-dial
// callback via closeAndAwaitDials, then waits for log EOF and finalizes. The
// callback must stop new callbacks and await existing ones even on failure.
// The caller must first wait for the workload and close all log writer copies.
// A nil callback or callback error records delivery loss. This method can
// block until EOF; a callback that violates its contract cannot be detected.
// Repeated calls retain the first outcome and return a fresh snapshot.
func (s *Stream) Finish(outcome Outcome, closeAndAwaitDials func() error) (ProfileCandidate, error) {
	s.once.Do(func() {
		if closeAndAwaitDials == nil || closeAndAwaitDials() != nil {
			outcome.DeliveryError = errors.New("dial callback delivery not confirmed")
		}
		if <-s.done != nil {
			outcome.DeliveryError = errors.New("log delivery failed")
		}
		s.collector.FinishOutcome(outcome)
		if outcome.DeliveryError != nil || outcome.ScannerError != nil {
			s.err = errors.New("candidate delivery incomplete")
		}
	})
	// Snapshot again to return detached slices and include any contract-violating
	// late callbacks in the loss flags rather than returning mutable shared data.
	return s.collector.Snapshot(), s.err
}
