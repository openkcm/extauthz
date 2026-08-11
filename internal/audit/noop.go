package audit

import (
	"context"

	"go.opentelemetry.io/collector/pdata/plog"
)

type NoopLogger struct{}

func (NoopLogger) SendEvent(ctx context.Context, logs plog.Logs) error { return nil }
