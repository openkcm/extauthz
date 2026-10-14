//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/valkey-io/valkey-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/openkcm/extauthz/internal/ratestore"
)

// startValkey spins up a Valkey container and returns a connected client.
func startValkey(t *testing.T) valkey.Client {
	t.Helper()
	_, client := startValkeyWithAddr(t)
	return client
}

// startValkeyWithAddr spins up a Valkey container and returns both its
// host:port address and a connected client.
func startValkeyWithAddr(t *testing.T) (string, valkey.Client) {
	t.Helper()
	ctx := context.Background()

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		Image:        "valkey/valkey:8-alpine",
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForListeningPort("6379/tcp").WithStartupTimeout(60 * time.Second),
		Started:      true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Terminate(ctx) })

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "6379/tcp")
	require.NoError(t, err)
	addr := fmt.Sprintf("%s:%s", host, port.Port())

	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{addr},
	})
	require.NoError(t, err)
	t.Cleanup(client.Close)
	return addr, client
}

// Sentinel master set name and the fixed ports used by startValkeySentinel.
const (
	sentinelMasterSet  = "mymaster"
	sentinelMasterPort = "6380"
	sentinelPort       = "26379"
)

// startValkeySentinel spins up a single container running a master and a
// sentinel that monitors it, and returns the host:port of the sentinel.
//
// A sentinel-mode client connects to the sentinel, asks it for the master
// address, and then connects to that address — so the master address the
// sentinel advertises must be reachable from the test process. We mirror
// valkey-go's own test setup: the sentinel monitors the master at a loopback
// address with a fixed port, and both container ports are bound to identical
// host ports so 127.0.0.1:<masterPort> resolves to the same container inside
// and outside Docker.
func startValkeySentinel(t *testing.T) string {
	t.Helper()
	ctx := context.Background()

	// Master in the background, then sentinel in the foreground monitoring it on
	// the loopback address with the fixed master port that matches the host
	// binding below.
	script := "valkey-server --save '' --appendonly no --port " + sentinelMasterPort + " &\n" +
		"printf 'sentinel monitor " + sentinelMasterSet + " 127.0.0.1 " + sentinelMasterPort + " 1\\n' > /tmp/sentinel.conf\n" +
		"exec valkey-server /tmp/sentinel.conf --sentinel"

	masterTCP := sentinelMasterPort + "/tcp"
	sentinelTCP := sentinelPort + "/tcp"
	loopback := netip.MustParseAddr("127.0.0.1")

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		Image:        "valkey/valkey:8-alpine",
		Entrypoint:   []string{"/bin/sh", "-c", script},
		ExposedPorts: []string{masterTCP, sentinelTCP},
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.PortBindings = network.PortMap{
				network.MustParsePort(masterTCP):   []network.PortBinding{{HostIP: loopback, HostPort: sentinelMasterPort}},
				network.MustParsePort(sentinelTCP): []network.PortBinding{{HostIP: loopback, HostPort: sentinelPort}},
			}
		},
		WaitingFor: wait.ForAll(
			wait.ForListeningPort(masterTCP),
			wait.ForListeningPort(sentinelTCP),
		).WithStartupTimeout(60 * time.Second),
		Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ctr.Terminate(ctx) })

	host, err := ctr.Host(ctx)
	require.NoError(t, err)
	return host + ":" + sentinelPort
}

// TestValkeyStore_SentinelResolvesMaster asserts that a sentinel-mode client
// resolves the master through the sentinel and that a rate-store observation
// round-trips to it: the store fires exactly once at the threshold, which only
// happens if the INCR/latch writes actually reached the sentinel-resolved
// master.
func TestValkeyStore_SentinelResolvesMaster(t *testing.T) {
	addr := startValkeySentinel(t)

	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{addr},
		Sentinel: valkey.SentinelOption{
			MasterSet: sentinelMasterSet,
		},
	})
	require.NoError(t, err)
	t.Cleanup(client.Close)

	store, err := ratestore.New(ratestore.Options{
		Client:    client,
		KeyPrefix: "sentinel-test",
		Threshold: 5,
		Window:    time.Hour,
	})
	require.NoError(t, err)

	ctx := context.Background()
	fired := 0
	for i := 1; i <= 10; i++ {
		f, err := store.Observe(ctx, "identity-sentinel")
		require.NoError(t, err)
		if f {
			fired++
		}
	}
	require.Equal(t, 1, fired, "should fire exactly once through the sentinel-resolved master")
}

// TestValkeyStore_SentinelTopologyRefresh asserts the sentinel client works
// with periodic topology refresh enabled: the background reconciler must not
// interfere with normal operation, and observations still round-trip to the
// resolved master.
func TestValkeyStore_SentinelTopologyRefresh(t *testing.T) {
	addr := startValkeySentinel(t)

	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{addr},
		Sentinel: valkey.SentinelOption{
			MasterSet:               sentinelMasterSet,
			TopologyRefreshInterval: time.Second,
		},
	})
	require.NoError(t, err)
	t.Cleanup(client.Close)

	store, err := ratestore.New(ratestore.Options{
		Client:    client,
		KeyPrefix: "sentinel-refresh",
		Threshold: 3,
		Window:    time.Hour,
	})
	require.NoError(t, err)

	ctx := context.Background()
	// Let the reconciler tick at least once before and after the writes.
	time.Sleep(1500 * time.Millisecond)
	fired := 0
	for i := 1; i <= 6; i++ {
		f, err := store.Observe(ctx, "identity-refresh")
		require.NoError(t, err)
		if f {
			fired++
		}
	}
	require.Equal(t, 1, fired, "should fire exactly once with topology refresh enabled")
}

// TestValkeyStore_FiresOnceAtThreshold asserts that a single fire happens when
// the threshold is crossed, and no earlier.
func TestValkeyStore_FiresOnceAtThreshold(t *testing.T) {
	client := startValkey(t)
	store, err := ratestore.New(ratestore.Options{
		Client:    client,
		KeyPrefix: "test",
		Threshold: 5,
		Window:    time.Hour, // large window so the test is not time-sensitive
	})
	require.NoError(t, err)

	ctx := context.Background()
	fired := 0
	for i := 1; i <= 10; i++ {
		f, err := store.Observe(ctx, "identity-a")
		require.NoError(t, err)
		if f {
			fired++
		}
	}
	require.Equal(t, 1, fired, "should fire exactly once when threshold is crossed")
}

// TestValkeyStore_FiresOnceUnderConcurrency simulates a fleet of pods observing
// the same identity concurrently; exactly one Observe must win the fire latch.
func TestValkeyStore_FiresOnceUnderConcurrency(t *testing.T) {
	client := startValkey(t)

	// Each "pod" gets its own store sharing the one Valkey (like separate pods).
	newStore := func() *ratestore.ValkeyStore {
		s, err := ratestore.New(ratestore.Options{
			Client:    client,
			KeyPrefix: "test",
			Threshold: 20,
			Window:    time.Hour,
		})
		require.NoError(t, err)
		return s
	}

	ctx := context.Background()
	const total = 100
	var fired atomic.Int64
	var wg sync.WaitGroup
	for range total {
		wg.Go(func() {
			s := newStore()
			f, err := s.Observe(ctx, "identity-b")
			require.NoError(t, err)
			if f {
				fired.Add(1)
			}
		})
	}
	wg.Wait()
	require.Equal(t, int64(1), fired.Load(), "exactly one observation across the fleet should fire")
}

// TestValkeyStore_Close asserts Close releases the store's Valkey client
// without error.
func TestValkeyStore_Close(t *testing.T) {
	client := startValkey(t)
	store, err := ratestore.New(ratestore.Options{
		Client:    client,
		KeyPrefix: "test",
		Threshold: 1,
		Window:    time.Hour,
	})
	require.NoError(t, err)
	require.NoError(t, store.Close())
}

// TestValkeyStore_DistinctIdentitiesIndependent asserts identities do not share
// a counter.
func TestValkeyStore_DistinctIdentitiesIndependent(t *testing.T) {
	client := startValkey(t)
	store, err := ratestore.New(ratestore.Options{
		Client:    client,
		KeyPrefix: "test",
		Threshold: 3,
		Window:    time.Hour,
	})
	require.NoError(t, err)

	ctx := context.Background()
	// Two observations each for two identities: neither reaches threshold 3.
	for _, id := range []string{"x", "y"} {
		for range 2 {
			f, err := store.Observe(ctx, id)
			require.NoError(t, err)
			require.False(t, f)
		}
	}
}

// TestService_RateDetectionEnabled boots the real binary with Valkey-backed
// rate detection enabled and drives unauthenticated requests through it. This
// exercises the business wiring (createRateStore, audit pipeline) and the
// Valkey store's Observe/Close against a live server, all under coverage.
func TestService_RateDetectionEnabled(t *testing.T) {
	addr, _ := startValkeyWithAddr(t)

	// Enable rate detection with a low threshold so a handful of requests
	// crosses it within the run.
	config := validConfig + fmt.Sprintf(`
valkey:
  address:
    value: %q
  prefix: extauthz-it
  secretRef:
    type: insecure
  rateDetection:
    enabled: true
    threshold: 3
    window: 1m
    countUnknown: true
`, addr)

	cleanup, err := writeFiles(config, trustedSubjects, policies, rsaPrivateKeyPEM)
	require.NoError(t, err)
	defer cleanup()

	// start the service in the background
	cmd := serviceCmd(t.Context(), "--graceful-shutdown=0")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Start())
	// Graceful stop so the rate store is closed and coverprofiles are written.
	defer func() {
		_ = syscall.Kill(cmd.Process.Pid, syscall.SIGTERM)
		_ = cmd.Wait()
		t.Logf("Stdout: %s\n", stdout.String())
		t.Logf("Stderr: %s\n", stderr.String())
	}()

	conn, err := grpc.NewClient("localhost:9092", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	client := envoy_auth.NewAuthorizationClient(conn)

	ctx := t.Context()
	// wait for the server to be ready
	for i := 100; i > 0; i-- {
		_, err := client.Check(ctx, nil)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Fire several credential-less (UNKNOWN) requests for the same tenant so the
	// burst counter crosses the threshold and the async audit dispatch runs.
	req := &envoy_auth.CheckRequest{Attributes: &envoy_auth.AttributeContext{
		Request: &envoy_auth.AttributeContext_Request{Http: &envoy_auth.AttributeContext_HttpRequest{
			Method: "GET", Host: "our.service.com", Path: "/cmk/v1/myTenantID/resource",
		}},
	}}
	for range 5 {
		resp, err := client.Check(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
	}

	// Give the async audit workers a moment to drain before shutdown.
	time.Sleep(200 * time.Millisecond)
}

// TestService_RateDetectionSentinel boots the real binary with Valkey-backed
// rate detection pointed at a sentinel (valkey.masterSet set) and drives
// unauthenticated requests through it. Because createRateStore builds a
// sentinel-mode client that eagerly resolves the master via the sentinel, a
// successful boot and request handling exercises the sentinel wiring end to
// end under coverage.
func TestService_RateDetectionSentinel(t *testing.T) {
	addr := startValkeySentinel(t)

	config := validConfig + fmt.Sprintf(`
valkey:
  address:
    value: %q
  masterSet: %q
  topologyRefreshInterval: 5s
  prefix: extauthz-it-sentinel
  secretRef:
    type: insecure
  rateDetection:
    enabled: true
    threshold: 3
    window: 1m
    countUnknown: true
`, addr, sentinelMasterSet)

	cleanup, err := writeFiles(config, trustedSubjects, policies, rsaPrivateKeyPEM)
	require.NoError(t, err)
	defer cleanup()

	// start the service in the background
	cmd := serviceCmd(t.Context(), "--graceful-shutdown=0")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Start())
	// Graceful stop so the rate store is closed and coverprofiles are written.
	defer func() {
		_ = syscall.Kill(cmd.Process.Pid, syscall.SIGTERM)
		_ = cmd.Wait()
		t.Logf("Stdout: %s\n", stdout.String())
		t.Logf("Stderr: %s\n", stderr.String())
	}()

	conn, err := grpc.NewClient("localhost:9092", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	client := envoy_auth.NewAuthorizationClient(conn)

	ctx := t.Context()
	// wait for the server to be ready
	for i := 100; i > 0; i-- {
		_, err := client.Check(ctx, nil)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Fire several credential-less (UNKNOWN) requests for the same tenant so the
	// burst counter crosses the threshold via the sentinel-resolved master.
	req := &envoy_auth.CheckRequest{Attributes: &envoy_auth.AttributeContext{
		Request: &envoy_auth.AttributeContext_Request{Http: &envoy_auth.AttributeContext_HttpRequest{
			Method: "GET", Host: "our.service.com", Path: "/cmk/v1/myTenantID/resource",
		}},
	}}
	for range 5 {
		resp, err := client.Check(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
	}

	// Give the async audit workers a moment to drain before shutdown.
	time.Sleep(200 * time.Millisecond)
}
