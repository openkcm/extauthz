//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

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
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "valkey/valkey:8-alpine",
			ExposedPorts: []string{"6379/tcp"},
			WaitingFor:   wait.ForListeningPort("6379/tcp").WithStartupTimeout(60 * time.Second),
		},
		Started: true,
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
