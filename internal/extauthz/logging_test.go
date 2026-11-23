package extauthz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openkcm/common-sdk/pkg/auth"
	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/openkcm/common-sdk/pkg/logger"
	"github.com/openkcm/common-sdk/pkg/otlp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/extauthz/internal/config"
	"github.com/openkcm/extauthz/internal/ratedetectionqueue"
	"github.com/openkcm/extauthz/internal/session"
)

func captureProductionLogs(t *testing.T) (context.Context, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("application:\n  name: extauthz\n"), 0o600))
	var cfg config.Config
	require.NoError(t, commoncfg.LoadConfig(&cfg, map[string]any{}, dir))
	assert.Equal(t, "info", cfg.Logger.Level)
	assert.Equal(t, commoncfg.JSONLoggerFormat, cfg.Logger.Format)
	cfg.Logger.Level = "debug"
	buf := new(bytes.Buffer)
	handler, err := logger.InitHandlerWithWriter(buf, cfg.Logger, cfg.Application)
	require.NoError(t, err)
	return slogctx.NewCtx(t.Context(), slog.New(handler)), buf
}

func TestCheck_ProductionLogCorrelationWithoutExport(t *testing.T) {
	initTestTelemetry(t)
	srv := newTestServer(t, nil, nil)
	for _, parent := range []string{"", "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-00"} {
		ctx, buf := captureProductionLogs(t)
		req := validRequest()
		req.Attributes.Request.Http.Headers[HeaderTraceparent] = parent
		_, err := srv.Check(ctx, req)
		require.NoError(t, err)
		lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
		require.NotEmpty(t, lines)
		var expectedTrace, expectedSpan any
		for _, line := range lines {
			var record map[string]any
			require.NoError(t, json.Unmarshal([]byte(line), &record))
			assert.Regexp(t, "^[0-9a-f]{32}$", record["traceId"])
			assert.Regexp(t, "^[0-9a-f]{16}$", record["spanId"])
			assert.NotEmpty(t, record["time"])
			assert.NotEmpty(t, record["level"])
			assert.Equal(t, "extauthz", record[commoncfg.AttrServiceName])
			if parent != "" {
				assert.Equal(t, knownTraceID, record["traceId"])
			}
			if expectedTrace == nil {
				expectedTrace, expectedSpan = record["traceId"], record["spanId"]
			}
			assert.Equal(t, expectedTrace, record["traceId"])
			assert.Equal(t, expectedSpan, record["spanId"])
		}
	}
}

func TestCredentialDiagnosticsExcludeCredentialSecrets(t *testing.T) {
	ctx, buf := captureProductionLogs(t)
	parseJWTHeader(ctx, "diagnostic-header!.payload.jwt-signature-secret")
	parsed := parseJWTHeader(ctx, "eyJhbGciOiJSUzI1NiJ9.diagnostic-payload.jwt-signature-secret")
	require.True(t, parsed.ok)
	jwtValidationError(ctx, errors.New("diagnostic-provider-error"), parsed)
	tracer, exp := newTestTracer(t)
	sm := new(MockSessionManager)
	sm.On("GetSession", mock.Anything, "session-cookie-secret", "tenant").Return(&session.Session{Valid: true}, nil)
	srv := newTestServer(t, tracer, sm)
	srv.checkSession(ctx, &http.Cookie{Value: "session-cookie-secret"}, "csrf-token-secret", requestInfo{tenantID: "tenant"})
	srv.checkClientCertCore(ctx, certInfo{subject: "diagnostic-certificate"}, "diagnostic-header-subject", requestInfo{})
	srv.trustedSubjectToRegion = map[string]string{"CN=minime": "region"}
	req := validRequest()
	req.Attributes.Request.Http.Path = "/foo/bar?sensitive-query=value"
	req.Attributes.Request.Http.Headers[HeaderForwardedClientCert] = "Hash=123;Subject=\"CN=minime\";Cert=" + x509CertPEMURLEncoded
	_, err := srv.Check(ctx, req)
	require.NoError(t, err)
	req.Attributes.Request.Http.Path = "/foo/bar"
	response, err := srv.Check(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, response.GetOkResponse())
	for _, header := range response.GetOkResponse().GetHeaders() {
		switch header.GetHeader().GetKey() {
		case auth.HeaderClientData:
			require.NotEmpty(t, header.GetHeader().GetValue())
			assert.Contains(t, buf.String(), header.GetHeader().GetValue())
		case auth.HeaderClientDataSignature:
			require.NotEmpty(t, header.GetHeader().GetValue())
			assert.NotContains(t, buf.String(), header.GetHeader().GetValue())
		}
	}
	// JWT headers/payloads, client data, provider errors, subjects and abbreviated hashes are
	// intentional diagnostics; signatures and raw session/CSRF credentials are not.
	for _, diagnostic := range []string{
		"diagnostic-header!", parsed.parts[0], parsed.parts[1], "diagnostic-provider-error",
		"diagnostic-certificate", "diagnostic-header-subject", "CN=minime",
		"secretHash", "cookieHash", "tokenHash",
	} {
		assert.Contains(t, buf.String(), diagnostic)
	}
	for _, secret := range []string{parsed.parts[2], "session-cookie-secret", "csrf-token-secret"} {
		assert.NotContains(t, buf.String(), secret)
	}
	for _, attr := range findCheckSpan(t, exp).Attributes {
		assert.NotContains(t, attr.Value.AsString(), "sensitive")
	}
}

func TestRateDetectionLogsKeepProducerCorrelationWithoutExport(t *testing.T) {
	initTestTelemetry(t)
	ctx, logs := captureProductionLogs(t)
	ctx = slogctx.With(ctx, "id", "request-id")
	ctx, cancel := context.WithCancel(ctx)
	ctx, producer := otel.Tracer("test").Start(ctx, "request")
	srv := newTestServer(t, nil, nil)
	queue := ratedetectionqueue.New(ratedetectionqueue.Options{Size: 1, Workers: 1})
	srv.rateDetectionQueue = queue
	var worker trace.SpanContext
	srv.submit(ctx, func(jobCtx context.Context) {
		worker = trace.SpanContextFromContext(jobCtx)
		slogctx.Warn(jobCtx, "rate store unavailable")
	})
	producer.End()
	cancel()
	queue.Start()
	require.NoError(t, queue.Close())
	var record map[string]any
	require.NoError(t, json.Unmarshal(logs.Bytes(), &record))
	assert.Equal(t, "request-id", record["id"])
	assert.Equal(t, producer.SpanContext().TraceID().String(), record["producer_trace_id"])
	assert.Equal(t, worker.TraceID().String(), record["traceId"])
	assert.Equal(t, worker.SpanID().String(), record["spanId"])
}

// initTestTelemetry exercises the same SDK initialization used by the binary.
func initTestTelemetry(t *testing.T) {
	t.Helper()
	previousProvider, previousPropagator := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	ctx, cancel := context.WithCancel(t.Context())
	stopped := make(chan struct{})
	require.NoError(t, otlp.Init(ctx, &commoncfg.Application{Name: "extauthz"},
		&commoncfg.Telemetry{}, &commoncfg.Logger{}, otlp.WithShutdownComplete(stopped)))
	t.Cleanup(func() {
		cancel()
		<-stopped
		otel.SetTracerProvider(previousProvider)
		otel.SetTextMapPropagator(previousPropagator)
	})
}
