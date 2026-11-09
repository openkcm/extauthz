package business

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/plog"
	"google.golang.org/grpc/codes"

	envoyauth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	otlpaudit "github.com/openkcm/common-sdk/pkg/otlp/audit"
	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/extauthz/internal/clientdata"
	"github.com/openkcm/extauthz/internal/config"
	"github.com/openkcm/extauthz/internal/extauthz"
)

func auditTestConfig(t *testing.T, endpoint string) *config.Config {
	t.Helper()
	dir := t.TempDir()
	trustedSubjects := filepath.Join(dir, "trusted-subjects.yaml")
	require.NoError(t, os.WriteFile(trustedSubjects, []byte("{}"), 0o600))

	cfg := &config.Config{
		ClientData: config.ClientData{SigningKeyIDFilePath: filepath.Join(dir, "keyId")},
		Cedar:      config.Cedar{PolicyPath: dir},
		CSRFSecret: commoncfg.SourceRef{Source: commoncfg.EmbeddedSourceValue, Value: "csrf-secret"},
	}
	cfg.MTLS.TrustedSubjectsYaml = trustedSubjects
	cfg.Audit.Endpoint = endpoint
	cfg.Audit.HTTPClient.Timeout = 5 * time.Second
	cfg.Audit.AdditionalProperties = "service: extauthz-test"
	cfg.Valkey.RateDetection.QueueSize = 1
	cfg.Valkey.RateDetection.Workers = 2
	return cfg
}

// An untrusted certificate produces a real DENIED decision without requiring
// an OIDC provider, session manager, or valid signing key.
func auditDeniedRequest(t *testing.T) *envoyauth.CheckRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "untrusted-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	require.NoError(t, err)
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &envoyauth.CheckRequest{Attributes: &envoyauth.AttributeContext{
		Request: &envoyauth.AttributeContext_Request{Http: &envoyauth.AttributeContext_HttpRequest{
			Id: "audit-request", Method: http.MethodGet, Host: "service.example", Path: "/restricted",
			Headers: map[string]string{extauthz.HeaderForwardedClientCert: "Cert=" + url.QueryEscape(string(encoded))},
		}},
	}}
}

func checkAuditDenied(t *testing.T, ctx context.Context, srv *extauthz.Server, req *envoyauth.CheckRequest) {
	t.Helper()
	type result struct {
		response *envoyauth.CheckResponse
		err      error
	}
	checked := make(chan result, 1)
	go func() {
		response, err := srv.Check(ctx, req)
		checked <- result{response: response, err: err}
	}()
	select {
	case res := <-checked:
		require.NoError(t, res.err)
		require.Equal(t, int32(codes.PermissionDenied), res.response.GetStatus().GetCode())
	case <-time.After(3 * time.Second):
		t.Fatal("authorization blocked on audit delivery")
	}
}

func TestCreateExtAuthZServer_QueuedAuditDeliveryIndependentOfValkey(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	releaseDelivery := sync.OnceFunc(func() { close(release) })
	payloads := make(chan []byte, 8)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		payloads <- payload
		select {
		case <-release:
			w.WriteHeader(http.StatusOK)
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(collector.Close)
	t.Cleanup(releaseDelivery)

	cfg := auditTestConfig(t, collector.URL)
	srv, err := createExtAuthZServer(t.Context(), cfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		releaseDelivery()
		require.NoError(t, srv.Close())
	})
	require.NoError(t, srv.Start())

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	req := auditDeniedRequest(t)
	checkAuditDenied(t, ctx, srv, req)
	var delivered [][]byte
	select {
	case payload := <-payloads:
		require.Contains(t, string(payload), "audit-request")
		delivered = append(delivered, payload)
	case <-time.After(3 * time.Second):
		t.Fatal("audit worker did not start delivery")
	}

	// All these events must fit in the independent audit queue, even though
	// Valkey is configured with only one buffered observation and two workers.
	// Delivery stays blocked so reusing those limits would drop an event.
	for _, id := range []string{"buffered-1", "buffered-2", "buffered-3"} {
		req.GetAttributes().GetRequest().GetHttp().Id = id
		checkAuditDenied(t, ctx, srv, req)
	}
	cancel()
	releaseDelivery()
	require.NoError(t, srv.Close())

	require.Len(t, payloads, 3, "Valkey queue limits must not drop audit events")
	for _, id := range []string{"buffered-1", "buffered-2", "buffered-3"} {
		payload := <-payloads
		require.Contains(t, string(payload), id)
		delivered = append(delivered, payload)
	}
	for _, payload := range delivered {
		logs, err := (&plog.JSONUnmarshaler{}).UnmarshalLogs(payload)
		require.NoError(t, err)
		require.Equal(t, 1, logs.LogRecordCount())
		attrs := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes()
		value, ok := attrs.Get("ext_authz.auth_type")
		require.True(t, ok)
		require.Equal(t, "x509", value.Str())
		value, ok = attrs.Get("service")
		require.True(t, ok)
		require.Equal(t, "extauthz-test", value.Str())
	}
}

func TestCreateExtAuthZServer_AuditDeliveryFailureIsLogged(t *testing.T) {
	t.Parallel()
	var attempts atomic.Int32
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(collector.Close)

	var output bytes.Buffer
	ctx := slogctx.NewCtx(t.Context(), slog.New(slog.NewJSONHandler(&output, nil)))
	srv, err := createExtAuthZServer(ctx, auditTestConfig(t, collector.URL))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, srv.Close()) })
	checkAuditDenied(t, ctx, srv, auditDeniedRequest(t))
	require.NoError(t, srv.Close())

	require.Greater(t, attempts.Load(), int32(1), "delivery failures must be retried")
	require.Contains(t, output.String(), "failed to deliver audit event after retries")
	require.Contains(t, output.String(), `"level":"ERROR"`)
}

func TestCreateExtAuthZServer_InvalidAuditConfig(t *testing.T) {
	t.Parallel()
	cfg := auditTestConfig(t, "http://collector.invalid/v1/logs")
	cfg.Audit.AdditionalProperties = "[invalid YAML"
	srv, err := createExtAuthZServer(t.Context(), cfg)
	require.ErrorContains(t, err, "creating audit logger")
	require.Nil(t, srv)
}

func TestCreateExtAuthZServer_RateStoreFailureAfterAuditSetup(t *testing.T) {
	t.Parallel()
	cfg := auditTestConfig(t, "http://collector.invalid/v1/logs")
	cfg.Valkey.RateDetection.Enabled = true
	cfg.Valkey.Address = commoncfg.SourceRef{Source: commoncfg.EmbeddedSourceValue}
	srv, err := createExtAuthZServer(t.Context(), cfg)
	require.ErrorContains(t, err, "valkey address must not be empty")
	require.Nil(t, srv)
}

func TestStartGRPCServer_StartFailureClosesAuditLogger(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	signer, err := clientdata.NewSigner(&commoncfg.FeatureGates{}, &config.ClientData{
		SigningKeyIDFilePath: filepath.Join(dir, "keyId"),
	})
	require.NoError(t, err)
	// Removing the configured directory makes the real signer fail to start.
	require.NoError(t, os.Remove(dir))
	sink, err := otlpaudit.NewLogger(&commoncfg.Audit{})
	require.NoError(t, err)
	logger := otlpaudit.NewQueuedLogger(sink, otlpaudit.QueuedOptions{})
	t.Cleanup(func() { require.NoError(t, logger.Close(context.Background())) })
	srv, err := extauthz.NewServer(extauthz.WithClientDataSigner(signer), extauthz.WithAuditLogger(logger))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, srv.Close()) })

	err = startGRPCServer(t.Context(), &config.Config{}, srv)
	require.ErrorContains(t, err, "path does not exist")
	require.ErrorContains(t, logger.SendEvent(plog.NewLogs()), "closed")
}
