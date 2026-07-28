package audit

import (
	"context"

	"go.opentelemetry.io/collector/pdata/plog"
)

type Logger interface {
	SendEvent(ctx context.Context, logs plog.Logs) error
}
