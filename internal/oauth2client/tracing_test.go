package oauth2client_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/openkcm/extauthz/internal/oauth2client"
)

// Routing OAuth2 construction through NewHTTPClient must preserve the template's
// mTLS settings and instrument the request exactly once.
func TestBuilderTracingPreservesMTLS(t *testing.T) {
	previousProvider, previousPropagator := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		require.NoError(t, tp.Shutdown(context.Background()))
		otel.SetTracerProvider(previousProvider)
		otel.SetTextMapPropagator(previousPropagator)
	})
	received := make(chan trace.SpanContext, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NotEmpty(t, r.TLS.PeerCertificates)
		received <- trace.SpanContextFromContext(otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header)))
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	defer server.Close()
	cert := server.TLS.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	require.NoError(t, err)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	builder := oauth2client.NewBuilder(commoncfg.OAuth2{
		Credentials: commoncfg.OAuth2Credentials{AuthMethod: commoncfg.OAuth2None},
		MTLS: &commoncfg.MTLS{
			Cert:     commoncfg.SourceRef{Source: commoncfg.EmbeddedSourceValue, Value: certPEM},
			CertKey:  commoncfg.SourceRef{Source: commoncfg.EmbeddedSourceValue, Value: keyPEM},
			ServerCA: &commoncfg.SourceRef{Source: commoncfg.EmbeddedSourceValue, Value: certPEM},
		},
	})
	client, err := builder("client-id")
	require.NoError(t, err)
	defer client.CloseIdleConnections()
	ctx := otel.GetTextMapPropagator().Extract(t.Context(), propagation.MapCarrier{
		"traceparent": "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	response, err := client.Do(req)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	remote := <-received
	assert.Equal(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", remote.TraceID().String())
	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assert.Equal(t, trace.SpanKindClient, spans[0].SpanKind)
	assert.Equal(t, remote.SpanID(), spans[0].SpanContext.SpanID())
}
