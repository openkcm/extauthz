package extauthz

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/openkcm/common-sdk/pkg/csrf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/genproto/googleapis/rpc/code"

	envoyauth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	slogctx "github.com/veqryn/slog-context"
	otelslogctx "github.com/veqryn/slog-context/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/openkcm/extauthz/internal/clientdata"
	"github.com/openkcm/extauthz/internal/config"
	"github.com/openkcm/extauthz/internal/policies/cedarpolicy"
	"github.com/openkcm/extauthz/internal/ratedetectionqueue"
	"github.com/openkcm/extauthz/internal/session"
)

// newTestTracer builds an SDK TracerProvider backed by an in-memory exporter
// and returns the tracer plus the exporter so tests can inspect finished
// spans. The composite W3C TraceContext + Baggage propagator is installed as
// the global TextMapPropagator so Check() can extract trace context the way
// it does in production.
func newTestTracer(t *testing.T) (trace.Tracer, *tracetest.InMemoryExporter) {
	t.Helper()

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
	})

	// Install the propagator globally for the duration of the test. The
	// global propagator is process-wide; tests in this package run
	// sequentially within the binary so a transient global set is acceptable.
	prevProp := otel.GetTextMapPropagator()
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	t.Cleanup(func() { otel.SetTextMapPropagator(prevProp) })

	return tp.Tracer("test"), exporter
}

// newTestServer builds an extauthz.Server suitable for tracing tests. If
// tracer is nil the default (global no-op) tracer is used.
func newTestServer(t *testing.T, tracer trace.Tracer, sessionManager sessionManagerInterface) *Server {
	t.Helper()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyId"), []byte("key01"), 0o644))
	require.NoError(t, generateKeyFile(filepath.Join(dir, "key01.pem")))

	pe, err := cedarpolicy.NewEngine(cedarpolicy.WithBytes("policies", []byte(cedarpolicies)))
	require.NoError(t, err)

	featureGates := &commoncfg.FeatureGates{
		clientdata.EnrichHeaderWithClientRegion: true,
		clientdata.EnrichHeaderWithClientType:   true,
	}
	signer, err := clientdata.NewSigner(featureGates, &config.ClientData{
		SigningKeyIDFilePath: filepath.Join(dir, "keyId"),
	})
	require.NoError(t, err)

	const csrfSecret = "secret"

	opts := []ServerOption{
		WithSessionPathPrefixes([]string{"/cmk/v1"}),
		WithClientDataSigner(signer),
		WithPolicyEngine(pe),
		WithFeatureGates(featureGates),
		WithCSRFSecret([]byte(csrfSecret)),
	}
	if sessionManager != nil {
		opts = append(opts, WithSessionManager(sessionManager))
	}
	if tracer != nil {
		opts = append(opts, WithTracer(tracer))
	}

	srv, err := NewServer(opts...)
	require.NoError(t, err)
	require.NoError(t, srv.Start())
	t.Cleanup(func() { _ = srv.Close() })

	return srv
}

func generateKeyFile(path string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return pem.Encode(f, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
}

const (
	// knownTraceID / knownParentSpan correspond to the fields encoded in the
	// fully-formed W3C traceparent value below.
	knownTraceID        = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	knownParentSpanID   = "bbbbbbbbbbbbbbbb"
	knownTraceparentVal = "00-" + knownTraceID + "-" + knownParentSpanID + "-01"
)

func validRequest() *envoyauth.CheckRequest {
	return &envoyauth.CheckRequest{
		Attributes: &envoyauth.AttributeContext{
			Request: &envoyauth.AttributeContext_Request{
				Http: &envoyauth.AttributeContext_HttpRequest{
					Method:  "GET",
					Host:    "our.service.com",
					Path:    "/foo/bar",
					Headers: map[string]string{},
				},
			},
		},
	}
}

func findCheckSpan(t *testing.T, exp *tracetest.InMemoryExporter) tracetest.SpanStub {
	t.Helper()

	spans := exp.GetSpans()
	for _, s := range spans {
		if s.Name == spanNameCheck {
			return s
		}
	}
	t.Fatalf("no %q span found in %d exported spans", spanNameCheck, len(spans))
	return tracetest.SpanStub{}
}

func spanAttr(span tracetest.SpanStub, key string) (string, bool) {
	for _, kv := range span.Attributes {
		if string(kv.Key) == key {
			return kv.Value.AsString(), true
		}
	}
	return "", false
}

func TestCheck_TracePropagation_TraceparentExtracted(t *testing.T) {
	tracer, exp := newTestTracer(t)
	srv := newTestServer(t, tracer, nil)

	req := validRequest()
	req.Attributes.Request.Http.Headers[HeaderTraceparent] = knownTraceparentVal

	_, err := srv.Check(t.Context(), req)
	require.NoError(t, err)

	span := findCheckSpan(t, exp)
	assert.Equal(t, knownTraceID, span.SpanContext.TraceID().String())
	assert.Equal(t, knownParentSpanID, span.Parent.SpanID().String())
}

func TestCheck_TracePropagation_NoTraceparent(t *testing.T) {
	tracer, exp := newTestTracer(t)
	srv := newTestServer(t, tracer, nil)

	_, err := srv.Check(t.Context(), validRequest())
	require.NoError(t, err)

	span := findCheckSpan(t, exp)
	assert.True(t, span.SpanContext.IsValid(), "span should still be emitted without traceparent")
	assert.False(t, span.Parent.IsValid(), "no parent expected when no traceparent")
}

func TestCheck_TracePropagation_MalformedTraceparent(t *testing.T) {
	tracer, exp := newTestTracer(t)
	srv := newTestServer(t, tracer, nil)

	req := validRequest()
	req.Attributes.Request.Http.Headers[HeaderTraceparent] = "garbage"

	_, err := srv.Check(t.Context(), req)
	require.NoError(t, err)

	span := findCheckSpan(t, exp)
	assert.True(t, span.SpanContext.IsValid())
	assert.False(t, span.Parent.IsValid())
}

func TestCheck_SpanAttributes(t *testing.T) {
	const csrfSecret = "secret"
	const sessionID = "mySessionID"
	csrfToken := csrf.NewToken(sessionID, []byte(csrfSecret))

	tests := []struct {
		name         string
		trustedSubj  map[string]string
		setupMocks   func(*MockSessionManager)
		request      *envoyauth.CheckRequest
		wantDecision string
		wantCode     code.Code
		wantStatus   codes.Code
	}{
		{
			name: "ALLOWED via x509",
			trustedSubj: map[string]string{
				"CN=minime": "minime-region",
			},
			request: &envoyauth.CheckRequest{Attributes: &envoyauth.AttributeContext{
				Request: &envoyauth.AttributeContext_Request{Http: &envoyauth.AttributeContext_HttpRequest{
					Method: "GET", Host: "our.service.com", Path: "/foo/bar",
					Headers: map[string]string{HeaderForwardedClientCert: "Hash=123;Subject=\"CN=minime\";Cert=" + x509CertPEMURLEncoded},
				}},
			}},
			wantDecision: "ALLOWED",
			wantCode:     code.Code_OK,
			wantStatus:   codes.Ok,
		},
		{
			name: "DENIED via untrusted x509",
			trustedSubj: map[string]string{
				"CN=minime": "minime-region",
			},
			request: &envoyauth.CheckRequest{Attributes: &envoyauth.AttributeContext{
				Request: &envoyauth.AttributeContext_Request{Http: &envoyauth.AttributeContext_HttpRequest{
					Method: "GET", Host: "our.service.com", Path: "/foo/bar",
					Headers: map[string]string{HeaderForwardedClientCert: "Hash=123;Subject=\"CN=austin\";Cert=" + x509CertPEMURLEncoded},
				}},
			}},
			wantDecision: "DENIED",
			wantCode:     code.Code_PERMISSION_DENIED,
			wantStatus:   codes.Error,
		},
		{
			name: "UNAUTHENTICATED via no credentials",
			request: &envoyauth.CheckRequest{Attributes: &envoyauth.AttributeContext{
				Request: &envoyauth.AttributeContext_Request{Http: &envoyauth.AttributeContext_HttpRequest{
					Method: "GET", Host: "our.service.com", Path: "/foo/bar",
					Headers: map[string]string{HeaderAuthorization: "Bearer token"},
				}},
			}},
			wantDecision: "UNAUTHENTICATED",
			wantCode:     code.Code_UNAUTHENTICATED,
			wantStatus:   codes.Error,
		},
		{
			name: "TENANT_BLOCKED via session manager",
			request: &envoyauth.CheckRequest{Attributes: &envoyauth.AttributeContext{
				Request: &envoyauth.AttributeContext_Request{Http: &envoyauth.AttributeContext_HttpRequest{
					Method: "GET", Host: "our.service.com", Path: "/cmk/v1/myTenantID/bar",
					Headers: map[string]string{
						HeaderCookie:    "__Host-Http-SESSION-myTenantID=" + sessionID,
						HeaderCSRFToken: csrfToken,
					},
				}},
			}},
			setupMocks: func(m *MockSessionManager) {
				m.On("GetSession", mock.Anything, sessionID, "myTenantID", mock.Anything).
					Return(nil, session.ErrTenantBlocked)
			},
			wantDecision: "TENANT_BLOCKED",
			wantCode:     code.Code_PERMISSION_DENIED,
			wantStatus:   codes.Error,
		},
		{
			name: "UNKNOWN via no credentials",
			request: &envoyauth.CheckRequest{Attributes: &envoyauth.AttributeContext{
				Request: &envoyauth.AttributeContext_Request{Http: &envoyauth.AttributeContext_HttpRequest{
					Method: "GET", Host: "our.service.com", Path: "/foo/bar",
					Headers: map[string]string{},
				}},
			}},
			wantDecision: "UNKNOWN",
			wantCode:     code.Code_UNAUTHENTICATED,
			wantStatus:   codes.Error,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tracer, exp := newTestTracer(t)
			sm := new(MockSessionManager)
			if tc.setupMocks != nil {
				tc.setupMocks(sm)
			}
			srv := newTestServer(t, tracer, sm)
			srv.trustedSubjectToRegion = tc.trustedSubj

			got, err := srv.Check(t.Context(), tc.request)
			require.NoError(t, err)
			assert.Equal(t, int32(tc.wantCode), got.GetStatus().GetCode())

			span := findCheckSpan(t, exp)
			decision, ok := spanAttr(span, spanAttrDecision)
			require.True(t, ok, "ext_authz.decision attribute missing")
			assert.Equal(t, tc.wantDecision, decision)
			assert.Equal(t, tc.wantStatus, span.Status.Code)
		})
	}
}

func TestCheck_AuthType(t *testing.T) {
	const csrfSecret = "secret"
	const sessionID = "mySessionID"
	csrfToken := csrf.NewToken(sessionID, []byte(csrfSecret))

	tests := []struct {
		name        string
		trustedSubj map[string]string
		setupMocks  func(*MockSessionManager)
		request     *envoyauth.CheckRequest
		wantType    string
	}{
		{
			name: "x509 only",
			trustedSubj: map[string]string{
				"CN=minime": "minime-region",
			},
			request: &envoyauth.CheckRequest{Attributes: &envoyauth.AttributeContext{
				Request: &envoyauth.AttributeContext_Request{Http: &envoyauth.AttributeContext_HttpRequest{
					Method: "GET", Host: "our.service.com", Path: "/foo/bar",
					Headers: map[string]string{HeaderForwardedClientCert: "Hash=123;Subject=\"CN=minime\";Cert=" + x509CertPEMURLEncoded},
				}},
			}},
			wantType: "x509",
		},
		{
			name: "jwt only",
			request: &envoyauth.CheckRequest{Attributes: &envoyauth.AttributeContext{
				Request: &envoyauth.AttributeContext_Request{Http: &envoyauth.AttributeContext_HttpRequest{
					Method: "GET", Host: "our.service.com", Path: "/foo/bar",
					Headers: map[string]string{HeaderAuthorization: "Bearer token"},
				}},
			}},
			wantType: "jwt",
		},
		{
			name: "session only",
			request: &envoyauth.CheckRequest{Attributes: &envoyauth.AttributeContext{
				Request: &envoyauth.AttributeContext_Request{Http: &envoyauth.AttributeContext_HttpRequest{
					Method: "GET", Host: "our.service.com", Path: "/cmk/v1/myTenantID/bar",
					Headers: map[string]string{
						HeaderCookie:    "__Host-Http-SESSION-myTenantID=" + sessionID,
						HeaderCSRFToken: csrfToken,
					},
				}},
			}},
			setupMocks: func(m *MockSessionManager) {
				m.On("GetSession", mock.Anything, sessionID, "myTenantID", mock.Anything).
					Return(&session.Session{
						Valid:      true,
						Subject:    "mySessionMe",
						Issuer:     "https://127.0.0.1:8443",
						GivenName:  "Chris",
						FamilyName: "Burkert",
					}, nil)
			},
			wantType: "session",
		},
		{
			name: "no credentials",
			request: &envoyauth.CheckRequest{Attributes: &envoyauth.AttributeContext{
				Request: &envoyauth.AttributeContext_Request{Http: &envoyauth.AttributeContext_HttpRequest{
					Method: "GET", Host: "our.service.com", Path: "/foo/bar",
					Headers: map[string]string{},
				}},
			}},
			wantType: "none",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tracer, exp := newTestTracer(t)
			sm := new(MockSessionManager)
			if tc.setupMocks != nil {
				tc.setupMocks(sm)
			}
			srv := newTestServer(t, tracer, sm)
			srv.trustedSubjectToRegion = tc.trustedSubj

			_, err := srv.Check(t.Context(), tc.request)
			require.NoError(t, err)

			span := findCheckSpan(t, exp)
			authType, ok := spanAttr(span, spanAttrAuthType)
			require.True(t, ok, "ext_authz.auth_type attribute missing")
			assert.Equal(t, tc.wantType, authType)
		})
	}
}

func TestCheck_LogsCarryTraceID(t *testing.T) {
	tracer, _ := newTestTracer(t)
	srv := newTestServer(t, tracer, nil)

	var buf bytes.Buffer
	// Install the slogotel handler so log entries automatically carry
	// TraceID / SpanID when the context has a recording span.
	handler := slogctx.NewHandler(
		slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}),
		&slogctx.HandlerOptions{
			Prependers: []slogctx.AttrExtractor{otelslogctx.ExtractTraceSpanID},
		},
	)
	prev := slog.Default()
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(prev) })

	req := validRequest()
	req.Attributes.Request.Http.Headers[HeaderTraceparent] = knownTraceparentVal

	_, err := srv.Check(t.Context(), req)
	require.NoError(t, err)

	logs := buf.String()
	assert.Contains(t, logs, knownTraceID, "expected log output to carry the inbound TraceID")
}

func TestCheck_NilRequest_HasSpan(t *testing.T) {
	tracer, exp := newTestTracer(t)
	srv := newTestServer(t, tracer, nil)

	resp, err := srv.Check(t.Context(), nil)
	require.NoError(t, err)
	assert.Equal(t, int32(code.Code_UNAUTHENTICATED), resp.GetStatus().GetCode())

	assert.True(t, findCheckSpan(t, exp).SpanContext.IsValid())
}

func TestCheck_AllowedRepairsMissingOrInvalidContext(t *testing.T) {
	for _, parent := range []string{"", "garbage",
		"00-00000000000000000000000000000000-bbbbbbbbbbbbbbbb-01",
		"00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-0000000000000000-01",
	} {
		t.Run(parent, func(t *testing.T) {
			tracer, exp := newTestTracer(t)
			srv := newTestServer(t, tracer, nil)
			srv.trustedSubjectToRegion = map[string]string{"CN=minime": "minime-region"}
			// Exercise both signed and unsigned allowed responses.
			if parent == "" {
				srv.clientDataSigner = nil
			}
			req := validRequest()
			headers := req.GetAttributes().GetRequest().GetHttp().GetHeaders()
			headers[HeaderForwardedClientCert] = "Hash=123;Subject=\"CN=minime\";Cert=" + x509CertPEMURLEncoded
			headers[HeaderTraceparent] = parent
			headers[HeaderTracestate] = "orphan=value"
			headers[HeaderBaggage] = "vendor=value"

			resp, err := srv.Check(t.Context(), req)
			require.NoError(t, err)
			require.Equal(t, int32(code.Code_OK), resp.GetStatus().GetCode())
			forwarded := propagation.MapCarrier{}
			for _, h := range resp.GetOkResponse().GetHeaders() {
				if h.GetHeader().GetKey() == HeaderTraceparent {
					assert.Equal(t, int32(2), int32(h.GetAppendAction()), "must overwrite, never append traceparent")
				}
				forwarded[h.GetHeader().GetKey()] = h.GetHeader().GetValue()
			}
			sc := trace.SpanContextFromContext(propagation.TraceContext{}.Extract(t.Context(), forwarded))
			require.True(t, sc.IsValid(), "allowed response must supply a valid replacement context")
			assert.Equal(t, findCheckSpan(t, exp).SpanContext.TraceID(), sc.TraceID())
			assert.Equal(t, findCheckSpan(t, exp).SpanContext.SpanID(), sc.SpanID())
			assert.Contains(t, resp.GetOkResponse().GetHeadersToRemove(), HeaderTracestate)
			assert.NotContains(t, resp.GetOkResponse().GetHeadersToRemove(), HeaderBaggage)
			assert.Equal(t, parent, headers[HeaderTraceparent], "request must not be mutated")
		})
	}
}

func TestCheck_HTTPParentLinksDistinctTransport(t *testing.T) {
	tracer, exp := newTestTracer(t)
	ctx, transport := tracer.Start(t.Context(), "transport")
	defer transport.End()
	srv := newTestServer(t, tracer, nil)
	req := validRequest()
	req.Attributes.Request.Http.Headers[HeaderTraceparent] = knownTraceparentVal
	req.Attributes.Request.Http.Headers[HeaderTracestate] = "vendor=value"
	_, err := srv.Check(ctx, req)
	require.NoError(t, err)
	span := findCheckSpan(t, exp)
	assert.Equal(t, knownTraceID, span.SpanContext.TraceID().String())
	assert.Equal(t, "vendor=value", span.SpanContext.TraceState().String())
	require.Len(t, span.Links, 1)
	assert.Equal(t, transport.SpanContext(), span.Links[0].SpanContext)
}

func TestCheck_TransportParentFallback(t *testing.T) {
	tracer, exp := newTestTracer(t)
	srv := newTestServer(t, tracer, nil)
	ctx := propagation.TraceContext{}.Extract(t.Context(), propagation.MapCarrier{HeaderTraceparent: knownTraceparentVal, HeaderTracestate: "vendor=value"})
	req := validRequest()
	req.Attributes.Request.Http.Headers[HeaderTraceparent] = "malformed"
	_, err := srv.Check(ctx, req)
	require.NoError(t, err)
	span := findCheckSpan(t, exp)
	assert.Equal(t, knownTraceID, span.SpanContext.TraceID().String())
	assert.Equal(t, knownParentSpanID, span.Parent.SpanID().String())
	assert.Equal(t, "vendor=value", span.SpanContext.TraceState().String())
}

func TestCheck_SigningFailureMarksSpanAsError(t *testing.T) {
	tracer, exp := newTestTracer(t)
	srv := newTestServer(t, tracer, nil)
	require.NoError(t, srv.clientDataSigner.Close())
	signer, err := clientdata.NewSigner(&commoncfg.FeatureGates{}, &config.ClientData{SigningKeyIDFilePath: filepath.Join(t.TempDir(), "missing-key-id")})
	require.NoError(t, err)
	srv.clientDataSigner = signer
	srv.trustedSubjectToRegion = map[string]string{"CN=minime": "region"}
	req := validRequest()
	req.Attributes.Request.Http.Headers[HeaderForwardedClientCert] = "Hash=123;Subject=\"CN=minime\";Cert=" + x509CertPEMURLEncoded
	response, err := srv.Check(t.Context(), req)
	require.NoError(t, err)
	assert.Equal(t, int32(code.Code_INTERNAL), response.GetStatus().GetCode())
	assert.Equal(t, codes.Error, findCheckSpan(t, exp).Status.Code)
}

func TestRateDetectionLinksProducerAfterRequestCancellation(t *testing.T) {
	tracer, exp := newTestTracer(t)
	srv := newTestServer(t, tracer, nil)
	queue := ratedetectionqueue.New(ratedetectionqueue.Options{Size: 1, Workers: 1})
	srv.rateDetectionQueue = queue
	ctx, cancel := context.WithCancel(t.Context())
	ctx, producer := tracer.Start(ctx, "request")
	var received trace.SpanContext
	var jobErr error
	srv.submit(ctx, func(jobCtx context.Context) {
		received = trace.SpanContextFromContext(jobCtx)
		jobErr = jobCtx.Err()
	})
	producer.End()
	cancel()
	queue.Start()
	require.NoError(t, queue.Close())
	require.NoError(t, jobErr)
	require.True(t, received.IsValid())
	assert.NotEqual(t, producer.SpanContext().TraceID(), received.TraceID())
	spans := exp.GetSpans()
	require.Len(t, spans, 2)
	assert.Equal(t, "ext_authz.rate_detection", spans[1].Name)
	require.Len(t, spans[1].Links, 1)
	assert.Equal(t, producer.SpanContext(), spans[1].Links[0].SpanContext)
}

func TestCheck_DefaultTracerKeepsAuthorizationDecision(t *testing.T) {
	// No WithTracer option: authorization works with the process-wide provider.
	srv := newTestServer(t, nil, nil)

	req := validRequest()
	req.Attributes.Request.Http.Headers[HeaderTraceparent] = knownTraceparentVal

	resp, err := srv.Check(t.Context(), req)
	require.NoError(t, err)
	// No credentials, decision is UNAUTHENTICATED — the call still succeeds
	// and the response matches the pre-change behavior.
	assert.Equal(t, int32(code.Code_UNAUTHENTICATED), resp.GetStatus().GetCode())
}

func TestMerge_KindAdoptedOnMoreRestrictive(t *testing.T) {
	r := checkResult{is: ALLOWED, kind: authKindX509}
	r.merge(checkResult{is: DENIED, kind: authKindSession})

	assert.Equal(t, DENIED, r.is)
	assert.Equal(t, authKindSession, r.kind, "kind should follow the more-restrictive result")
}

func TestMerge_KindRetainedWhenLessRestrictive(t *testing.T) {
	r := checkResult{is: DENIED, kind: authKindSession}
	r.merge(checkResult{is: ALLOWED, kind: authKindX509})

	assert.Equal(t, DENIED, r.is)
	assert.Equal(t, authKindSession, r.kind, "kind should stay when other result is less restrictive")
}

func TestAuthType_Labels(t *testing.T) {
	cases := []struct {
		kind authKind
		want string
	}{
		{authKindNone, "none"},
		{authKindX509, "x509"},
		{authKindJWT, "jwt"},
		{authKindSession, "session"},
	}
	for _, tc := range cases {
		r := checkResult{kind: tc.kind}
		got := r.authType()
		assert.Equal(t, tc.want, got)
	}
}

func TestCheck_AllowedDoesNotStripTraceHeaders(t *testing.T) {
	tracer, _ := newTestTracer(t)
	srv := newTestServer(t, tracer, nil)
	srv.trustedSubjectToRegion = map[string]string{"CN=minime": "minime-region"}

	req := &envoyauth.CheckRequest{Attributes: &envoyauth.AttributeContext{
		Request: &envoyauth.AttributeContext_Request{Http: &envoyauth.AttributeContext_HttpRequest{
			Method: "GET", Host: "our.service.com", Path: "/foo/bar",
			Headers: map[string]string{
				HeaderForwardedClientCert: "Hash=123;Subject=\"CN=minime\";Cert=" + x509CertPEMURLEncoded,
				HeaderTraceparent:         knownTraceparentVal,
				HeaderTracestate:          "vendor=value",
				HeaderBaggage:             "k1=v1",
			},
		}},
	}}

	resp, err := srv.Check(t.Context(), req)
	require.NoError(t, err)
	require.Equal(t, int32(code.Code_OK), resp.GetStatus().GetCode())

	ok := resp.GetOkResponse()
	require.NotNil(t, ok, "expected OkResponse on ALLOWED")

	// HeadersToRemove MUST NOT contain trace propagation headers.
	for _, h := range ok.GetHeadersToRemove() {
		assert.NotEqual(t, HeaderTraceparent, h, "traceparent must not be stripped")
		assert.NotEqual(t, HeaderTracestate, h, "tracestate must not be stripped")
		assert.NotEqual(t, HeaderBaggage, h, "baggage must not be stripped")
	}
	// HeadersToRemove MUST still contain x-forwarded-client-cert (pre-existing behavior).
	assert.Contains(t, ok.GetHeadersToRemove(), HeaderForwardedClientCert)

	// HeadersToAdd MUST NOT overwrite trace propagation headers.
	for _, h := range ok.GetHeaders() {
		k := h.GetHeader().GetKey()
		assert.NotEqual(t, HeaderTraceparent, k, "traceparent must not be overwritten")
		assert.NotEqual(t, HeaderTracestate, k, "tracestate must not be overwritten")
		assert.NotEqual(t, HeaderBaggage, k, "baggage must not be overwritten")
	}
}
