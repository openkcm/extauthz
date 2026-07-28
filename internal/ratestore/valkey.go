package ratestore

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/valkey-io/valkey-go"
)

// luaObserve counts one observation for an identity and latches the burst event
// exactly once per (window, identity). It runs entirely on the server so the
// window boundary is derived from the Valkey server clock (via TIME), not from
// per-pod wall clocks, eliminating cross-pod skew.
//
// KEYS[1] is the base key, which must contain a {hash-tag} so the two derived
// keys (counter and fire-latch) always land in the same cluster slot.
// ARGV: 1=windowSeconds 2=threshold 3=windowTTLMillis 4=cooldownMillis
//
// Returns 1 when this call first crosses the threshold and wins the latch
// (i.e. the caller should emit the audit event), 0 otherwise.
//
//nolint:dupword // Lua's "end" keyword repeats in this script.
const luaObserve = `
local t = redis.call('TIME')
local now = tonumber(t[1])
local window = tonumber(ARGV[1])
local threshold = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
local cooldown = tonumber(ARGV[4])
local bucket = math.floor(now / window)
local counterKey = KEYS[1] .. ':' .. bucket
local firedKey = KEYS[1] .. ':fired:' .. bucket
local count = redis.call('INCR', counterKey)
if count == 1 then
  redis.call('PEXPIRE', counterKey, ttl)
end
if count >= threshold then
  local ok = redis.call('SET', firedKey, '1', 'NX', 'PX', cooldown)
  if ok then
    return 1
  end
end
return 0
`

// ValkeyStore is a RateStore backed by a Valkey server (single, sentinel or
// cluster, depending on the addresses supplied at construction).
type ValkeyStore struct {
	client    valkey.Client
	script    *valkey.Lua
	keyPrefix string

	windowSeconds int64
	threshold     int64
	windowTTLMs   int64
	cooldownMs    int64
}

// Options configures a ValkeyStore.
type Options struct {
	// Client is a connected Valkey client. Required.
	Client valkey.Client

	// KeyPrefix namespaces all keys written by this store (cfg.Valkey.Prefix).
	KeyPrefix string

	// Threshold is the number of observations within Window that triggers a
	// single fired result.
	Threshold int64

	// Window is the tumbling window size.
	Window time.Duration

	// Cooldown suppresses further fired results for the same identity/window
	// after one has fired. Defaults to Window when zero.
	Cooldown time.Duration
}

// New creates a ValkeyStore from the given options.
func New(opts Options) (*ValkeyStore, error) {
	if opts.Client == nil {
		return nil, errors.New("ratestore: valkey client must not be nil")
	}
	if opts.Threshold < 1 {
		return nil, errors.New("ratestore: threshold must be >= 1")
	}
	if opts.Window <= 0 {
		return nil, errors.New("ratestore: window must be > 0")
	}
	cooldown := opts.Cooldown
	if cooldown <= 0 {
		cooldown = opts.Window
	}

	windowSeconds := max(int64(opts.Window.Seconds()), 1)

	return &ValkeyStore{
		client:        opts.Client,
		script:        valkey.NewLuaScript(luaObserve),
		keyPrefix:     opts.KeyPrefix,
		windowSeconds: windowSeconds,
		threshold:     opts.Threshold,
		// Grace of two windows so late arrivals in a bucket still count; the key
		// self-expires, so idle identities cost nothing.
		windowTTLMs: opts.Window.Milliseconds() * 2,
		cooldownMs:  cooldown.Milliseconds(),
	}, nil
}

// Observe implements RateStore.
func (s *ValkeyStore) Observe(ctx context.Context, hkey string) (bool, error) {
	// The {hkey} hash tag keeps the counter and fire-latch keys in the same
	// cluster slot, which the Lua script requires.
	baseKey := fmt.Sprintf("%s:unauth:{%s}", s.keyPrefix, hkey)

	res := s.script.Exec(ctx, s.client,
		[]string{baseKey},
		[]string{
			strconv.FormatInt(s.windowSeconds, 10),
			strconv.FormatInt(s.threshold, 10),
			strconv.FormatInt(s.windowTTLMs, 10),
			strconv.FormatInt(s.cooldownMs, 10),
		},
	)
	err := res.Error()
	if err != nil {
		return false, fmt.Errorf("ratestore: observe: %w", err)
	}

	fired, err := res.ToInt64()
	if err != nil {
		return false, fmt.Errorf("ratestore: decode result: %w", err)
	}

	return fired == 1, nil
}

// Close implements RateStore.
func (s *ValkeyStore) Close() error {
	s.client.Close()
	return nil
}
