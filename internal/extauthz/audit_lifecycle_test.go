package extauthz

import (
	"context"
	"errors"
	"testing"

	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	otlpaudit "github.com/openkcm/common-sdk/pkg/otlp/audit"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/openkcm/extauthz/internal/metric"
	"github.com/openkcm/extauthz/internal/ratedetectionqueue"
	"github.com/openkcm/extauthz/internal/session"
)

func TestRecordDecision_RejectedAuditEventIsCounted(t *testing.T) {
	t.Parallel()
	for _, decision := range []checkResultCode{UNAUTHENTICATED, DENIED} {
		t.Run(decision.String(), func(t *testing.T) {
			t.Parallel()
			reader := sdkmetric.NewManualReader()
			provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
			t.Cleanup(func() { require.NoError(t, provider.Shutdown(context.Background())) })
			metrics, err := metric.New(provider.Meter("audit-test"))
			require.NoError(t, err)
			sink, err := otlpaudit.NewLogger(&commoncfg.Audit{})
			require.NoError(t, err)
			logger := otlpaudit.NewQueuedLogger(sink, otlpaudit.QueuedOptions{})
			// A closed SDK queue rejects enqueueing without contacting a collector.
			require.NoError(t, logger.Close(t.Context()))
			srv, err := NewServer(WithAuditLogger(logger), WithMetrics(metrics), WithRateStore(&fakeRateStore{fire: true}))
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, srv.Close()) })

			srv.recordDecision(t.Context(),
				checkResult{is: decision, subject: "user", kind: authKindJWT},
				requestInfo{id: "request", tenantID: "tenant", path: "/restricted", method: "GET"},
			)

			var data metricdata.ResourceMetrics
			require.NoError(t, reader.Collect(t.Context(), &data))
			var dropped int64
			for _, scope := range data.ScopeMetrics {
				for _, m := range scope.Metrics {
					if m.Name != "extauthz_audit_dropped_total" {
						continue
					}
					sum, ok := m.Data.(metricdata.Sum[int64])
					require.True(t, ok)
					for _, point := range sum.DataPoints {
						dropped += point.Value
					}
				}
			}
			require.Equal(t, int64(1), dropped)
		})
	}
}

type shutdownAuditLogger struct {
	captureLogger

	closeErr      error
	contextErr    error
	eventsAtClose int
	hasDeadline   bool
}

func (l *shutdownAuditLogger) Close(ctx context.Context) error {
	l.contextErr = ctx.Err()
	_, l.hasDeadline = ctx.Deadline()
	l.eventsAtClose = l.count()
	return l.closeErr
}

type shutdownRateStore struct {
	fakeRateStore

	closed bool
}

func (s *shutdownRateStore) Close() error {
	s.closed = true
	return nil
}

type shutdownSessionManager struct {
	closeErr error
	closed   bool
}

func (m *shutdownSessionManager) GetSession(context.Context, string, string) (*session.Session, error) {
	return &session.Session{}, nil
}

func (m *shutdownSessionManager) Close() error {
	m.closed = true
	return m.closeErr
}

func TestClose_DrainsObservationsBeforeClosingAuditLogger(t *testing.T) {
	t.Parallel()
	logger := &shutdownAuditLogger{}
	store := &shutdownRateStore{fire: true}
	queue := ratedetectionqueue.New(ratedetectionqueue.Options{Size: 16, Workers: 1})
	srv, err := NewServer(WithAuditLogger(logger), WithRateStore(store), WithRateDetectionQueue(queue))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, srv.Close()) })
	require.NoError(t, srv.Start())

	for range 16 {
		srv.recordDecision(t.Context(),
			checkResult{is: UNAUTHENTICATED, subject: "user", kind: authKindJWT},
			requestInfo{id: "request", tenantID: "tenant", path: "/restricted", method: "GET"},
		)
	}
	require.NoError(t, srv.Close())
	require.Equal(t, 16, logger.eventsAtClose, "all observations must enqueue before the audit logger closes")
	require.NoError(t, logger.contextErr, "audit draining must not inherit server cancellation")
	require.True(t, logger.hasDeadline, "audit draining must have a shutdown deadline")
	require.True(t, store.closed)
}

func TestClose_AuditFailureStillClosesOtherDependencies(t *testing.T) {
	t.Parallel()
	logger := &shutdownAuditLogger{closeErr: context.DeadlineExceeded}
	store := &shutdownRateStore{}
	sessionErr := errors.New("session connection close failed")
	manager := &shutdownSessionManager{closeErr: sessionErr}
	srv, err := NewServer(WithAuditLogger(logger), WithRateStore(store), WithSessionManager(manager))
	require.NoError(t, err)

	err = srv.Close()
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.ErrorIs(t, err, sessionErr)
	require.True(t, store.closed, "audit failure must not skip rate-store cleanup")
	require.True(t, manager.closed, "audit failure must not skip session cleanup")
	require.NoError(t, logger.contextErr)
	require.True(t, logger.hasDeadline)
}
