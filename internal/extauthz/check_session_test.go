package extauthz

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/openkcm/session-manager/pkg/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/openkcm/extauthz/internal/clientdata"
	"github.com/openkcm/extauthz/internal/config"
	"github.com/openkcm/extauthz/internal/oidc"
	"github.com/openkcm/extauthz/internal/policies/cedarpolicy"
)

// MockSessionCache is a mock type for the SessionCache interface
type MockSessionCache struct {
	mock.Mock
}

func (m *MockSessionCache) LoadSession(ctx context.Context, sessionID string) (session.Session, error) {
	args := m.Called(ctx, sessionID)
	if args.Get(0) == nil {
		return session.Session{}, args.Error(1)
	}
	//nolint:forcetypeassert
	return args.Get(0).(session.Session), args.Error(1)
}

// MockOIDCHandler is a mock type for the oidc handler interface
type MockOIDCHandler struct {
	mock.Mock
}

func (m *MockOIDCHandler) Introspect(ctx context.Context, issuer, bearerToken, introspectToken string, useCache bool) (oidc.Introspection, error) {
	args := m.Called(ctx, issuer, bearerToken, introspectToken, useCache)
	if args.Get(0) == nil {
		return oidc.Introspection{}, args.Error(1)
	}
	//nolint:forcetypeassert
	return args.Get(0).(oidc.Introspection), args.Error(1)
}

func (m *MockOIDCHandler) ParseAndValidate(ctx context.Context, rawToken string, userclaims any, useCache bool) error {
	args := m.Called(ctx, rawToken, userclaims, useCache)
	if args.Get(0) == nil {
		return args.Error(1)
	}
	return args.Error(0)
}

func TestCheckSession(t *testing.T) {
	// create the test cases
	tests := []struct {
		name           string
		cookie         *http.Cookie
		tenantID       string
		method         string
		host           string
		path           string
		setupMocks     func(*MockSessionCache, *MockOIDCHandler)
		expectedResult checkResult
	}{
		{
			name:           "zero values",
			expectedResult: checkResult{is: UNKNOWN},
		}, {
			name:   "LoadSession fails",
			cookie: &http.Cookie{Name: "session", Value: ""},
			setupMocks: func(sc *MockSessionCache, jh *MockOIDCHandler) {
				sc.On("LoadSession", mock.Anything, "").
					Return(nil, errors.New("session load error"))
			},
			expectedResult: checkResult{is: UNAUTHENTICATED},
		}, {
			name:   "Introspect fails",
			cookie: &http.Cookie{Name: "session", Value: ""},
			setupMocks: func(sc *MockSessionCache, jh *MockOIDCHandler) {
				sc.On("LoadSession", mock.Anything, "").
					Return(session.Session{}, nil)
				jh.On("Introspect", mock.Anything, "", "", "", false).
					Return(oidc.Introspection{}, errors.New("introspect error"))
			},
			expectedResult: checkResult{is: UNAUTHENTICATED},
		}, {
			name:   "Introspect inactive",
			cookie: &http.Cookie{Name: "session", Value: ""},
			setupMocks: func(sc *MockSessionCache, jh *MockOIDCHandler) {
				sc.On("LoadSession", mock.Anything, "").
					Return(session.Session{}, nil)
				jh.On("Introspect", mock.Anything, "", "", "", false).
					Return(oidc.Introspection{Active: false}, nil)
			},
			expectedResult: checkResult{is: UNAUTHENTICATED},
		}, {
			name:   "Policy deny",
			cookie: &http.Cookie{Name: "session", Value: ""},
			setupMocks: func(sc *MockSessionCache, jh *MockOIDCHandler) {
				sc.On("LoadSession", mock.Anything, "").
					Return(session.Session{}, nil)
				jh.On("Introspect", mock.Anything, "", "", "", false).
					Return(oidc.Introspection{Active: true}, nil)
			},
			expectedResult: checkResult{is: DENIED},
		}, {
			name:   "Policy deny method",
			cookie: &http.Cookie{Name: "session", Value: ""},
			method: "POST",
			host:   "my.service.com",
			path:   "/foo/bar",
			setupMocks: func(sc *MockSessionCache, jh *MockOIDCHandler) {
				sc.On("LoadSession", mock.Anything, "").
					Return(session.Session{
						Issuer: "https://127.0.0.1:8443",
					}, nil)
				jh.On("Introspect", mock.Anything, "https://127.0.0.1:8443", "", "", false).
					Return(oidc.Introspection{Active: true}, nil)
			},
			expectedResult: checkResult{is: DENIED},
		}, {
			name:   "Policy deny host",
			cookie: &http.Cookie{Name: "session", Value: ""},
			method: "GET",
			host:   "your.service.com",
			path:   "/foo/bar",
			setupMocks: func(sc *MockSessionCache, jh *MockOIDCHandler) {
				sc.On("LoadSession", mock.Anything, "").
					Return(session.Session{
						Issuer: "https://127.0.0.1:8443",
					}, nil)
				jh.On("Introspect", mock.Anything, "https://127.0.0.1:8443", "", "", true).
					Return(oidc.Introspection{Active: true}, nil)
			},
			expectedResult: checkResult{is: DENIED},
		}, {
			name:   "Policy deny path",
			cookie: &http.Cookie{Name: "session", Value: ""},
			method: "GET",
			host:   "your.service.com",
			path:   "/foo/bar/baz",
			setupMocks: func(sc *MockSessionCache, jh *MockOIDCHandler) {
				sc.On("LoadSession", mock.Anything, "").
					Return(session.Session{
						Issuer: "https://127.0.0.1:8443",
					}, nil)
				jh.On("Introspect", mock.Anything, "https://127.0.0.1:8443", "", "", true).
					Return(oidc.Introspection{Active: true}, nil)
			},
			expectedResult: checkResult{is: DENIED},
		}, {
			name:   "Policy allow",
			cookie: &http.Cookie{Name: "session", Value: ""},
			method: "GET",
			host:   "my.service.com",
			path:   "/foo/bar",
			setupMocks: func(sc *MockSessionCache, jh *MockOIDCHandler) {
				sc.On("LoadSession", mock.Anything, "").
					Return(session.Session{
						Issuer: "https://127.0.0.1:8443",
					}, nil)
				jh.On("Introspect", mock.Anything, "https://127.0.0.1:8443", "", "", true).
					Return(oidc.Introspection{Active: true}, nil)
			},
			expectedResult: checkResult{is: ALLOWED},
		},
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			ctx := t.Context()

			mockSessionCache := new(MockSessionCache)
			mockOIDCHandler := new(MockOIDCHandler)
			if tc.setupMocks != nil {
				tc.setupMocks(mockSessionCache, mockOIDCHandler)
			}

			pe, err := cedarpolicy.NewEngine(cedarpolicy.WithBytes("my policies", []byte(cedarpolicies)))
			if err != nil {
				t.Fatalf("could not create policy engine: %s", err)
			}

			signer, err := clientdata.NewSigner(&commoncfg.FeatureGates{
				clientdata.DisableClientDataComputation: true,
			}, &config.ClientData{})
			if err != nil {
				t.Fatalf("could not create clientdata signer: %s", err)
			}

			srv, err := NewServer(
				WithSessionCache(mockSessionCache),
				WithOIDCHandler(mockOIDCHandler),
				WithPolicyEngine(pe),
				WithClientDataSigner(signer),
			)
			if err != nil {
				t.Fatalf("could not create server: %s", err)
			}

			// Act
			result := srv.checkSession(ctx, tc.cookie, tc.tenantID, tc.method, tc.host, tc.path)

			// Assert
			assert.Equal(t, tc.expectedResult.is, result.is)
			mockSessionCache.AssertExpectations(t)
			mockOIDCHandler.AssertExpectations(t)
		})
	}
}
