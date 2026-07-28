package metric_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	appmetric "github.com/openkcm/extauthz/internal/metric"
)

// newTestMetrics returns a Metrics wired to an in-memory reader plus a collect
// func that returns the current scope metrics.
func newTestMetrics(t *testing.T) (*appmetric.Metrics, func() []metricdata.Metrics) {
	t.Helper()

	reader := metric.NewManualReader()
	provider := metric.NewMeterProvider(metric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })

	m, err := appmetric.New(provider.Meter("test"))
	require.NoError(t, err)

	collect := func() []metricdata.Metrics {
		var rm metricdata.ResourceMetrics
		require.NoError(t, reader.Collect(context.Background(), &rm))
		if len(rm.ScopeMetrics) == 0 {
			return nil
		}
		return rm.ScopeMetrics[0].Metrics
	}
	return m, collect
}

// sumFor returns the aggregated int64 sum recorded for the named instrument.
func sumFor(t *testing.T, metrics []metricdata.Metrics, name string) int64 {
	t.Helper()
	for _, m := range metrics {
		if m.Name != name {
			continue
		}
		switch agg := m.Data.(type) {
		case metricdata.Sum[int64]:
			var total int64
			for _, dp := range agg.DataPoints {
				total += dp.Value
			}
			return total
		default:
			t.Fatalf("instrument %q has unexpected aggregation %T", name, agg)
		}
	}
	t.Fatalf("instrument %q not found", name)
	return 0
}

func TestNew_NilMeterUsesGlobal(t *testing.T) {
	t.Parallel()

	m, err := appmetric.New(nil)
	require.NoError(t, err)
	require.NotNil(t, m)
}

func TestMetrics_RecordsInstruments(t *testing.T) {
	t.Parallel()

	m, collect := newTestMetrics(t)
	ctx := context.Background()

	m.IncUnauthenticated(ctx, "jwt")
	m.IncUnauthenticated(ctx, "jwt")
	m.IncUnauthorized(ctx, "x509", "DENIED")
	m.IncDropped(ctx)
	m.IncRateStoreError(ctx)
	m.IncPanic(ctx)
	m.AddQueueDepth(ctx, 3)
	m.AddQueueDepth(ctx, -1)

	metrics := collect()
	require.Equal(t, int64(2), sumFor(t, metrics, "extauthz_unauthenticated_total"))
	require.Equal(t, int64(1), sumFor(t, metrics, "extauthz_unauthorized_total"))
	require.Equal(t, int64(1), sumFor(t, metrics, "extauthz_audit_dropped_total"))
	require.Equal(t, int64(1), sumFor(t, metrics, "extauthz_ratestore_errors_total"))
	require.Equal(t, int64(1), sumFor(t, metrics, "extauthz_audit_panics_total"))
	require.Equal(t, int64(2), sumFor(t, metrics, "extauthz_audit_queue_depth"))
}

// TestMetrics_NilReceiverIsNoop asserts every method is safe to call on a nil
// *Metrics, so call sites need not guard.
func TestMetrics_NilReceiverIsNoop(t *testing.T) {
	t.Parallel()

	var m *appmetric.Metrics
	ctx := context.Background()

	require.NotPanics(t, func() {
		m.IncUnauthenticated(ctx, "jwt")
		m.IncUnauthorized(ctx, "x509", "DENIED")
		m.IncDropped(ctx)
		m.IncRateStoreError(ctx)
		m.IncPanic(ctx)
		m.AddQueueDepth(ctx, 1)
	})
}
