// Package metric holds the OpenTelemetry instruments used to observe the audit
// pipeline. Labels are limited to low-cardinality dimensions (auth_type,
// decision) so a hostile client cannot explode the metric cardinality;
// per-subject / per-issuer detection is the job of the Valkey rate store.
package metric

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const meterName = "github.com/openkcm/extauthz/internal/metric"

const (
	attrAuthType = "auth_type"
	attrDecision = "decision"
)

// Metrics bundles the audit-pipeline instruments. All methods are safe to call
// on a nil *Metrics (they become no-ops), so call sites need not guard.
type Metrics struct {
	unauthenticated metric.Int64Counter
	unauthorized    metric.Int64Counter
	dropped         metric.Int64Counter
	rateStoreErrors metric.Int64Counter
	panics          metric.Int64Counter
	queueDepth      metric.Int64UpDownCounter
}

// New builds the audit instruments from the given meter. When meter is nil the
// global MeterProvider installed by otlp.Init is used. It returns an error if
// any instrument fails to register.
func New(meter metric.Meter) (*Metrics, error) {
	if meter == nil {
		meter = otel.Meter(meterName)
	}

	unauthenticated, err := meter.Int64Counter(
		"extauthz_unauthenticated_total",
		metric.WithDescription("Total unauthenticated (UNKNOWN/UNAUTHENTICATED) Check results observed."),
	)
	if err != nil {
		return nil, err
	}

	unauthorized, err := meter.Int64Counter(
		"extauthz_unauthorized_total",
		metric.WithDescription("Total unauthorised (TENANT_BLOCKED/DENIED) Check results observed."),
	)
	if err != nil {
		return nil, err
	}

	dropped, err := meter.Int64Counter(
		"extauthz_audit_dropped_total",
		metric.WithDescription("Audit events dropped because the async dispatch queue was full."),
	)
	if err != nil {
		return nil, err
	}

	rateStoreErrors, err := meter.Int64Counter(
		"extauthz_ratestore_errors_total",
		metric.WithDescription("Errors returned by the Valkey rate store while observing a request."),
	)
	if err != nil {
		return nil, err
	}

	panics, err := meter.Int64Counter(
		"extauthz_audit_panics_total",
		metric.WithDescription("Audit dispatch jobs that panicked and were recovered by the worker pool."),
	)
	if err != nil {
		return nil, err
	}

	queueDepth, err := meter.Int64UpDownCounter(
		"extauthz_audit_queue_depth",
		metric.WithDescription("Current number of audit events buffered in the async dispatch queue."),
	)
	if err != nil {
		return nil, err
	}

	return &Metrics{
		unauthenticated: unauthenticated,
		unauthorized:    unauthorized,
		dropped:         dropped,
		rateStoreErrors: rateStoreErrors,
		panics:          panics,
		queueDepth:      queueDepth,
	}, nil
}

// IncUnauthenticated records an observed unauthenticated result.
func (m *Metrics) IncUnauthenticated(ctx context.Context, authType string) {
	if m == nil {
		return
	}
	m.unauthenticated.Add(ctx, 1, metric.WithAttributes(attribute.String(attrAuthType, authType)))
}

// IncUnauthorized records an observed unauthorised result.
func (m *Metrics) IncUnauthorized(ctx context.Context, authType, decision string) {
	if m == nil {
		return
	}
	m.unauthorized.Add(ctx, 1, metric.WithAttributes(
		attribute.String(attrAuthType, authType),
		attribute.String(attrDecision, decision),
	))
}

// IncDropped records an audit event that was dropped due to a full queue.
func (m *Metrics) IncDropped(ctx context.Context) {
	if m == nil {
		return
	}
	m.dropped.Add(ctx, 1)
}

// IncRateStoreError records a Valkey rate-store failure.
func (m *Metrics) IncRateStoreError(ctx context.Context) {
	if m == nil {
		return
	}
	m.rateStoreErrors.Add(ctx, 1)
}

// IncPanic records an audit dispatch job that panicked and was recovered.
func (m *Metrics) IncPanic(ctx context.Context) {
	if m == nil {
		return
	}
	m.panics.Add(ctx, 1)
}

// AddQueueDepth adjusts the current audit queue depth by delta (+1 on enqueue,
// -1 on drain).
func (m *Metrics) AddQueueDepth(ctx context.Context, delta int64) {
	if m == nil {
		return
	}
	m.queueDepth.Add(ctx, delta)
}
