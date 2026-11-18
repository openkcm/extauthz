package audit

import (
	"context"

	"go.opentelemetry.io/collector/pdata/plog"
)

type NoopLogger struct{}

func (NoopLogger) SendEvent(logs plog.Logs) error { return nil }

func (NoopLogger) Close(ctx context.Context) error { return nil }
