// Package ratestore provides cross-pod detection of unauthenticated request
// bursts. A RateStore counts observations for an identity within a tumbling
// window and reports, exactly once per (window, identity) across the whole
// fleet, when the count first crosses a threshold.
//
// The Valkey-backed implementation performs the count-and-latch atomically in a
// single Lua script evaluated on the server, so no distributed lock or leader
// election is needed and pod clock skew does not affect window boundaries.
package ratestore

import "context"

// RateStore observes an unauthenticated request for the given identity key and
// reports whether this observation is the one that should emit the burst audit
// event. Implementations must be safe for concurrent use.
type RateStore interface {
	// Observe records one unauthenticated request for hkey. It returns fired ==
	// true for exactly one observation per (window, identity) across the fleet:
	// the one that first crosses the threshold and wins the emit latch.
	Observe(ctx context.Context, hkey string) (fired bool, err error)

	// Close releases any resources held by the store.
	Close() error
}

// Noop is a RateStore that never fires. It is used when rate detection is
// disabled so call sites can invoke Observe unconditionally.
type Noop struct{}

func (Noop) Observe(_ context.Context, _ string) (bool, error) { return false, nil }
func (Noop) Close() error                                      { return nil }
