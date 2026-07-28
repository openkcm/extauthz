package extauthz

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"

	"go.opentelemetry.io/collector/pdata/plog"

	otlpaudit "github.com/openkcm/common-sdk/pkg/otlp/audit"
	slogctx "github.com/veqryn/slog-context"
)

// unspecified is the placeholder for audit metadata fields that the SDK
// constructors require (userInitiatorID, tenantID) but that are unknown for
// anonymous / failed-credential traffic. NewEventMetadata rejects empty values.
const unspecified = "UNSPECIFIED"

// recordDecision emits audit signals for a non-ALLOWED Check() decision. The
// synchronous cost is a metric increment plus a non-blocking job submission.
func (srv *Server) recordDecision(ctx context.Context, result checkResult, reqInfo requestInfo) {
	authType := result.authType()

	switch result.is {
	case UNAUTHENTICATED, UNKNOWN:
		srv.metrics.IncUnauthenticated(ctx, authType)
		srv.recordUnauthenticated(ctx, result, reqInfo, authType)
	case TENANT_BLOCKED, DENIED:
		srv.metrics.IncUnauthorized(ctx, authType, result.is.String())
		srv.recordUnauthorized(result, reqInfo, authType)
	case ALLOWED:
	}
}

// recordUnauthenticated runs the cross-pod burst detection and sends a single
// audit event when the observation crosses the fleet-wide threshold.
func (srv *Server) recordUnauthenticated(ctx context.Context, result checkResult, reqInfo requestInfo, authType string) {
	// UNKNOWN means no credentials were presented at all; only count it when
	// enabled, so health probes / anonymous public traffic are not counted.
	if result.is == UNKNOWN && !srv.countUnknown {
		return
	}

	hkey, ok := srv.burstKey(result, reqInfo)
	if !ok {
		return
	}

	srv.submit(ctx, func(jobCtx context.Context) {
		fired, err := srv.rateStore.Observe(jobCtx, hkey)
		if err != nil {
			srv.metrics.IncRateStoreError(jobCtx)
			slogctx.Warn(jobCtx, LogPrefixCheck+"rate store observe failed", "error", err)
			return
		}
		if !fired {
			return
		}

		logs, err := srv.buildUnauthenticatedEvent(result, reqInfo, authType)
		if err != nil {
			slogctx.Warn(jobCtx, LogPrefixCheck+"failed to build unauthenticated event", "error", err)
			return
		}
		err = srv.audit.SendEvent(jobCtx, logs)
		if err != nil {
			slogctx.Warn(jobCtx, LogPrefixCheck+"failed to send unauthenticated event", "error", err)
		}
	})
}

// recordUnauthorized sends an unauthorised-request audit event immediately;
// unauthorised requests are a per-request fact and need no rate detection.
func (srv *Server) recordUnauthorized(result checkResult, reqInfo requestInfo, authType string) {
	srv.submit(context.Background(), func(jobCtx context.Context) {
		logs, err := srv.buildUnauthorizedEvent(result, reqInfo, authType)
		if err != nil {
			slogctx.Warn(jobCtx, LogPrefixCheck+"failed to build unauthorized event", "error", err)
			return
		}
		err = srv.audit.SendEvent(jobCtx, logs)
		if err != nil {
			slogctx.Warn(jobCtx, LogPrefixCheck+"failed to send unauthorized event", "error", err)
		}
	})
}

// burstKey returns the hashed identity key used to window unauthenticated
// bursts, and whether a usable key exists. It prefers the issuer (present only
// on JWT/session paths); failed/absent credentials have no issuer, so they key
// on a coarse per-tenant bucket instead.
func (srv *Server) burstKey(result checkResult, reqInfo requestInfo) (string, bool) {
	var key string
	switch {
	case result.authContext[contextKeyIssuer] != "":
		key = "iss:" + result.authContext[contextKeyIssuer]
	case reqInfo.tenantID != "":
		key = "tenant:" + reqInfo.tenantID
	default:
		return "", false
	}

	// Hash to bound key length and avoid storing raw issuer/tenant in Valkey.
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:16]), true
}

func (srv *Server) buildUnauthenticatedEvent(result checkResult, reqInfo requestInfo, authType string) (plog.Logs, error) {
	meta, err := srv.eventMetadata(result, reqInfo)
	if err != nil {
		return plog.Logs{}, err
	}
	logs, err := otlpaudit.NewUnauthenticatedRequestEvent(meta)
	if err != nil {
		return plog.Logs{}, err
	}
	annotateAuthType(logs, authType)
	return logs, nil
}

func (srv *Server) buildUnauthorizedEvent(result checkResult, reqInfo requestInfo, authType string) (plog.Logs, error) {
	meta, err := srv.eventMetadata(result, reqInfo)
	if err != nil {
		return plog.Logs{}, err
	}
	logs, err := otlpaudit.NewUnauthorizedRequestEvent(meta, reqInfo.path, reqInfo.method)
	if err != nil {
		return plog.Logs{}, err
	}
	annotateAuthType(logs, authType)
	return logs, nil
}

// eventMetadata builds the SDK EventMetadata, substituting UNSPECIFIED for the
// required-but-unknown identity fields of anonymous / failed-credential traffic.
func (srv *Server) eventMetadata(result checkResult, reqInfo requestInfo) (otlpaudit.EventMetadata, error) {
	userInitiatorID := cmp.Or(result.subject, unspecified)
	tenantID := cmp.Or(reqInfo.tenantID, unspecified)
	return otlpaudit.NewEventMetadata(userInitiatorID, tenantID, reqInfo.id)
}

// annotateAuthType records the credential channel on the audit log records as a
// low-cardinality attribute.
func annotateAuthType(logs plog.Logs, authType string) {
	rl := logs.ResourceLogs()
	for i := range rl.Len() {
		sl := rl.At(i).ScopeLogs()
		for j := range sl.Len() {
			lr := sl.At(j).LogRecords()
			for k := range lr.Len() {
				lr.At(k).Attributes().PutStr(spanAttrAuthType, authType)
			}
		}
	}
}

// submit runs the job on the async worker pool when configured; without a queue
// it runs synchronously (only used in tests / when no queue is wired).
func (srv *Server) submit(ctx context.Context, job func(ctx context.Context)) {
	if srv.auditQueue != nil {
		srv.auditQueue.Submit(ctx, job)
		return
	}
	job(ctx)
}
