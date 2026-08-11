package extauthz

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/plog"

	envoyauth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/openkcm/extauthz/internal/auditqueue"
)

// fakeRateStore is a controllable RateStore for testing recordDecision.
type fakeRateStore struct {
	mu       sync.Mutex
	observed []string
	fire     bool
	err      error
}

func (f *fakeRateStore) Observe(_ context.Context, hkey string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.observed = append(f.observed, hkey)
	return f.fire, f.err
}

func (f *fakeRateStore) Close() error { return nil }

func (f *fakeRateStore) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.observed...)
}

// captureLogger records the audit events it is asked to send.
type captureLogger struct {
	mu   sync.Mutex
	logs []plog.Logs
	err  error
}

func (c *captureLogger) SendEvent(_ context.Context, logs plog.Logs) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logs = append(c.logs, logs)
	return c.err
}

func (c *captureLogger) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.logs)
}

// newAuditTestServer builds a Server wired with the given fakes and no async
// queue, so recordDecision runs synchronously and assertions need no goroutine
// sync.
func newAuditTestServer(t *testing.T, rs *fakeRateStore, logger *captureLogger, countUnknown bool) *Server {
	t.Helper()
	srv, err := NewServer(
		WithRateStore(rs),
		WithAuditLogger(logger),
		WithCountUnknown(countUnknown),
	)
	require.NoError(t, err)
	return srv
}

func TestRecordDecision_Unauthenticated(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		result       checkResult
		reqInfo      requestInfo
		countUnknown bool
		fire         bool
		wantObserve  bool
		wantKeyPfx   string
		wantEvents   int
	}{
		{
			name: "issuer present keys on issuer and fires",
			result: checkResult{
				is:          UNAUTHENTICATED,
				subject:     "sub-1",
				kind:        authKindJWT,
				authContext: map[string]string{contextKeyIssuer: "https://issuer.example"},
			},
			reqInfo:     requestInfo{id: "r1", tenantID: "t1", path: "/p", method: "GET"},
			fire:        true,
			wantObserve: true,
			wantEvents:  1,
		},
		{
			name: "issuer present but below threshold does not emit",
			result: checkResult{
				is:          UNAUTHENTICATED,
				authContext: map[string]string{contextKeyIssuer: "https://issuer.example"},
			},
			reqInfo:     requestInfo{id: "r1", tenantID: "t1"},
			fire:        false,
			wantObserve: true,
			wantEvents:  0,
		},
		{
			name:        "no issuer falls back to tenant bucket",
			result:      checkResult{is: UNAUTHENTICATED},
			reqInfo:     requestInfo{id: "r1", tenantID: "t1"},
			fire:        true,
			wantObserve: true,
			wantEvents:  1,
		},
		{
			name:        "no issuer and no tenant is skipped",
			result:      checkResult{is: UNAUTHENTICATED},
			reqInfo:     requestInfo{id: "r1"},
			fire:        true,
			wantObserve: false,
			wantEvents:  0,
		},
		{
			name:         "UNKNOWN not counted by default",
			result:       checkResult{is: UNKNOWN},
			reqInfo:      requestInfo{id: "r1", tenantID: "t1"},
			countUnknown: false,
			fire:         true,
			wantObserve:  false,
			wantEvents:   0,
		},
		{
			name:         "UNKNOWN counted when enabled",
			result:       checkResult{is: UNKNOWN},
			reqInfo:      requestInfo{id: "r1", tenantID: "t1"},
			countUnknown: true,
			fire:         true,
			wantObserve:  true,
			wantEvents:   1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rs := &fakeRateStore{fire: tc.fire}
			logger := &captureLogger{}
			srv := newAuditTestServer(t, rs, logger, tc.countUnknown)

			srv.recordDecision(context.Background(), tc.result, tc.reqInfo)

			if tc.wantObserve {
				require.Len(t, rs.calls(), 1)
			} else {
				require.Empty(t, rs.calls())
			}
			require.Equal(t, tc.wantEvents, logger.count())
		})
	}
}

func TestRecordDecision_Unauthorized(t *testing.T) {
	t.Parallel()

	for _, code := range []checkResultCode{TENANT_BLOCKED, DENIED} {
		t.Run(code.String(), func(t *testing.T) {
			t.Parallel()
			rs := &fakeRateStore{}
			logger := &captureLogger{}
			srv := newAuditTestServer(t, rs, logger, false)

			srv.recordDecision(context.Background(),
				checkResult{is: code, subject: "sub", kind: authKindJWT},
				requestInfo{id: "r1", tenantID: "t1", path: "/foo", method: "POST"},
			)

			// Unauthorised is per-request: emit immediately, never touch the store.
			require.Empty(t, rs.calls())
			require.Equal(t, 1, logger.count())
		})
	}
}

func TestRecordDecision_Allowed(t *testing.T) {
	t.Parallel()
	rs := &fakeRateStore{fire: true}
	logger := &captureLogger{}
	srv := newAuditTestServer(t, rs, logger, true)

	srv.recordDecision(context.Background(), checkResult{is: ALLOWED}, requestInfo{id: "r1", tenantID: "t1"})

	require.Empty(t, rs.calls())
	require.Zero(t, logger.count())
}

func TestRecordDecision_RateStoreErrorDoesNotEmit(t *testing.T) {
	t.Parallel()
	rs := &fakeRateStore{fire: true, err: errors.New("valkey down")}
	logger := &captureLogger{}
	srv := newAuditTestServer(t, rs, logger, false)

	srv.recordDecision(context.Background(),
		checkResult{is: UNAUTHENTICATED, authContext: map[string]string{contextKeyIssuer: "iss"}},
		requestInfo{id: "r1", tenantID: "t1"},
	)

	require.Len(t, rs.calls(), 1)
	require.Zero(t, logger.count())
}

func TestRecordDecision_EmptySubjectTenantUsesUnspecified(t *testing.T) {
	t.Parallel()
	// Empty subject and tenant must still produce a valid event (metadata
	// constructor rejects empty values, so UNSPECIFIED must be substituted).
	rs := &fakeRateStore{fire: true}
	logger := &captureLogger{}
	srv := newAuditTestServer(t, rs, logger, false)

	srv.recordDecision(context.Background(),
		checkResult{is: DENIED},
		requestInfo{id: "r1", path: "/x", method: "GET"},
	)

	require.Equal(t, 1, logger.count(), "event should be built with UNSPECIFIED metadata")
}

func TestBurstKey_Deterministic(t *testing.T) {
	t.Parallel()
	srv := newAuditTestServer(t, &fakeRateStore{}, &captureLogger{}, false)

	k1, ok1 := srv.burstKey(checkResult{authContext: map[string]string{contextKeyIssuer: "iss"}}, requestInfo{tenantID: "t1"})
	k2, ok2 := srv.burstKey(checkResult{authContext: map[string]string{contextKeyIssuer: "iss"}}, requestInfo{tenantID: "t2"})
	require.True(t, ok1)
	require.True(t, ok2)
	// Issuer takes precedence over tenant, so different tenants with the same
	// issuer share a key.
	require.Equal(t, k1, k2)

	kt, okt := srv.burstKey(checkResult{}, requestInfo{tenantID: "t1"})
	require.True(t, okt)
	require.NotEqual(t, k1, kt)
}

// TestCheck_EmitsUnauthorizedEvent drives the full Check() path and asserts that
// a permission-denied decision produces exactly one unauthorised audit event.
func TestCheck_EmitsUnauthorizedEvent(t *testing.T) {
	t.Parallel()
	logger := &captureLogger{}
	srv := newAuditTestServer(t, &fakeRateStore{}, logger, false)

	// A trusted-but-unauthorised x509 subject: authenticates, then the (empty)
	// policy denies, yielding PERMISSION_DENIED.
	srv.trustedSubjectToRegion = map[string]string{"CN=minime": "region"}

	req := &envoyauth.CheckRequest{
		Attributes: &envoyauth.AttributeContext{
			Request: &envoyauth.AttributeContext_Request{
				Http: &envoyauth.AttributeContext_HttpRequest{
					Method:  "GET",
					Host:    "our.service.com",
					Path:    "/foo/bar",
					Headers: map[string]string{HeaderForwardedClientCert: "Hash=123;Subject=\"CN=minime\";Cert=" + x509CertPEMURLEncoded},
				},
			},
		},
	}

	_, err := srv.Check(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, 1, logger.count(), "unauthorised decision should emit one audit event")
}

// TestCheck_UnauthenticatedFiresOnThreshold drives Check() for an
// unauthenticated request and asserts the burst event fires only when the rate
// store reports the threshold crossed.
func TestCheck_UnauthenticatedFiresOnThreshold(t *testing.T) {
	t.Parallel()
	rs := &fakeRateStore{fire: true}
	logger := &captureLogger{}
	// No credentials at all yields UNKNOWN, so enable countUnknown to exercise
	// the burst path from a credential-less request.
	srv := newAuditTestServer(t, rs, logger, true)
	// Configure the session path prefix so the tenant ID is extracted from the
	// path and keys the burst window.
	require.NoError(t, WithSessionPathPrefixes([]string{"/cmk/v1"})(srv))

	req := &envoyauth.CheckRequest{
		Attributes: &envoyauth.AttributeContext{
			Request: &envoyauth.AttributeContext_Request{
				Http: &envoyauth.AttributeContext_HttpRequest{
					Method:  "GET",
					Host:    "our.service.com",
					Path:    "/cmk/v1/myTenantID/bar",
					Headers: map[string]string{},
				},
			},
		},
	}

	_, err := srv.Check(context.Background(), req)
	require.NoError(t, err)
	require.Len(t, rs.calls(), 1)
	require.Equal(t, 1, logger.count())
}

// TestAuditServerOptions_RejectNil asserts each audit-related ServerOption
// rejects a nil dependency rather than installing it.
func TestAuditServerOptions_RejectNil(t *testing.T) {
	t.Parallel()

	tests := map[string]ServerOption{
		"audit logger": WithAuditLogger(nil),
		"rate store":   WithRateStore(nil),
		"audit queue":  WithAuditQueue(nil),
		"metrics":      WithMetrics(nil),
	}
	for name, opt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.Error(t, opt(&Server{}))
		})
	}
}

// submit branch is exercised; the queue is drained on Close.
func TestRecordDecision_AsyncQueueDispatch(t *testing.T) {
	t.Parallel()
	rs := &fakeRateStore{}
	logger := &captureLogger{}
	queue := auditqueue.New(auditqueue.Options{Size: 8, Workers: 1})
	srv, err := NewServer(
		WithRateStore(rs),
		WithAuditLogger(logger),
		WithAuditQueue(queue),
	)
	require.NoError(t, err)
	require.NoError(t, srv.Start())

	srv.recordDecision(context.Background(),
		checkResult{is: DENIED, subject: "sub", kind: authKindJWT},
		requestInfo{id: "r1", tenantID: "t1", path: "/foo", method: "POST"},
	)

	// Close drains buffered jobs, so the event is delivered by the time it
	// returns.
	require.NoError(t, srv.Close())
	require.Equal(t, 1, logger.count())
}

// TestRecordDecision_SendEventErrorIsSwallowed asserts a failing audit sink does
// not propagate out of recordDecision (errors are logged, not returned).
func TestRecordDecision_SendEventErrorIsSwallowed(t *testing.T) {
	t.Parallel()
	rs := &fakeRateStore{fire: true}
	logger := &captureLogger{err: errors.New("collector unreachable")}
	srv := newAuditTestServer(t, rs, logger, false)

	require.NotPanics(t, func() {
		srv.recordDecision(context.Background(),
			checkResult{is: DENIED, subject: "sub"},
			requestInfo{id: "r1", tenantID: "t1", path: "/x", method: "GET"},
		)
	})
	// The send was attempted even though it failed.
	require.Equal(t, 1, logger.count())
}
