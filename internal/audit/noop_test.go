package audit_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/plog"

	"github.com/openkcm/extauthz/internal/audit"
)

// TestNoopLogger_SendEvent asserts the no-op logger accepts any logs without
// error, satisfying the audit.Logger interface used when audit delivery is off.
func TestNoopLogger_SendEvent(t *testing.T) {
	t.Parallel()

	var logger audit.Logger = audit.NoopLogger{}
	require.NoError(t, logger.SendEvent(context.Background(), plog.NewLogs()))
}
