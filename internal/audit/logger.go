package audit

import (
	"context"

	"go.opentelemetry.io/collector/pdata/plog"
)

// Logger queues events for background delivery and drains them on shutdown.
type Logger interface {
	SendEvent(logs plog.Logs) error
	Close(ctx context.Context) error
}
