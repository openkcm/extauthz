package ratestore

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/valkey-io/valkey-go"
)

// stubClient satisfies valkey.Client for construction-time tests. New never
// calls any method on the client, so the embedded nil interface is never
// dereferenced; it exists only to pass the non-nil guard.
type stubClient struct{ valkey.Client }

func TestNew_Validation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		opts    Options
		wantErr string
	}{
		{
			name:    "nil client",
			opts:    Options{Threshold: 1, Window: time.Minute},
			wantErr: "valkey client must not be nil",
		},
		{
			name:    "threshold zero",
			opts:    Options{Client: stubClient{}, Threshold: 0, Window: time.Minute},
			wantErr: "threshold must be >= 1",
		},
		{
			name:    "threshold negative",
			opts:    Options{Client: stubClient{}, Threshold: -3, Window: time.Minute},
			wantErr: "threshold must be >= 1",
		},
		{
			name:    "window zero",
			opts:    Options{Client: stubClient{}, Threshold: 1, Window: 0},
			wantErr: "window must be > 0",
		},
		{
			name:    "window negative",
			opts:    Options{Client: stubClient{}, Threshold: 1, Window: -time.Second},
			wantErr: "window must be > 0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store, err := New(tc.opts)
			require.Error(t, err)
			require.Nil(t, store)
			require.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestNew_DerivedFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		window            time.Duration
		cooldown          time.Duration
		threshold         int64
		wantWindowSeconds int64
		wantWindowTTLMs   int64
		wantCooldownMs    int64
	}{
		{
			name:              "explicit cooldown is honoured",
			window:            time.Minute,
			cooldown:          2 * time.Minute,
			threshold:         50,
			wantWindowSeconds: 60,
			wantWindowTTLMs:   120_000, // window * 2
			wantCooldownMs:    120_000,
		},
		{
			name:              "zero cooldown defaults to window",
			window:            5 * time.Minute,
			cooldown:          0,
			threshold:         10,
			wantWindowSeconds: 300,
			wantWindowTTLMs:   600_000,
			wantCooldownMs:    300_000, // == window
		},
		{
			name:              "negative cooldown defaults to window",
			window:            time.Minute,
			cooldown:          -time.Second,
			threshold:         1,
			wantWindowSeconds: 60,
			wantWindowTTLMs:   120_000,
			wantCooldownMs:    60_000,
		},
		{
			name:              "sub-second window clamps windowSeconds to 1",
			window:            500 * time.Millisecond,
			cooldown:          0,
			threshold:         1,
			wantWindowSeconds: 1,    // max(int64(0.5), 1)
			wantWindowTTLMs:   1000, // 500ms * 2
			wantCooldownMs:    500,  // cooldown defaults to window
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store, err := New(Options{
				Client:    stubClient{},
				KeyPrefix: "test",
				Threshold: tc.threshold,
				Window:    tc.window,
				Cooldown:  tc.cooldown,
			})
			require.NoError(t, err)
			require.Equal(t, tc.wantWindowSeconds, store.windowSeconds)
			require.Equal(t, tc.threshold, store.threshold)
			require.Equal(t, tc.wantWindowTTLMs, store.windowTTLMs)
			require.Equal(t, tc.wantCooldownMs, store.cooldownMs)
		})
	}
}

func TestNoop(t *testing.T) {
	t.Parallel()

	var n Noop
	fired, err := n.Observe(context.Background(), "any-identity")
	require.NoError(t, err)
	require.False(t, fired, "Noop must never fire")
	require.NoError(t, n.Close())
}

// TestNoop_ImplementsRateStore is a compile-time guarantee that Noop satisfies
// the interface Check() depends on.
func TestNoop_ImplementsRateStore(t *testing.T) {
	t.Parallel()
	var _ RateStore = Noop{}
}
