package extauthz

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/openkcm/extauthz/internal/clientdata"
	"github.com/openkcm/extauthz/internal/config"
	"github.com/openkcm/extauthz/internal/policies/cedarpolicy"
	"github.com/openkcm/extauthz/internal/session"
)

// MockSessionManager is a mock type for the oidc handler interface
type MockSessionManager struct {
	mock.Mock
}

func (m *MockSessionManager) GetSession(ctx context.Context, sessionID, tenantID, fingerprint string) (*session.Session, error) {
	args := m.Called(ctx, sessionID, tenantID, fingerprint)
	if args.Get(0) == nil {
		return &session.Session{}, args.Error(1)
	}
	//nolint:forcetypeassert
	return args.Get(0).(*session.Session), args.Error(1)
}

func TestCheckSession(t *testing.T) {
	// create the test cases
	tests := []struct {
		name           string
		cookie         *http.Cookie
		tenantID       string
		fingerprint    string
		method         string
		host           string
		path           string
		setupMocks     func(*MockSessionManager)
		expectedResult checkResult
	}{
		{
			name:           "zero values",
			expectedResult: checkResult{is: UNKNOWN},
		}, {
			name:   "GetSession fails",
			cookie: &http.Cookie{Name: "session", Value: ""},
			setupMocks: func(sm *MockSessionManager) {
				sm.On("GetSession", mock.Anything, "", "", "").
					Return(nil, errors.New("get session error"))
			},
			expectedResult: checkResult{is: UNAUTHENTICATED},
		}, {
			name:   "Invalid session",
			cookie: &http.Cookie{Name: "session", Value: ""},
			setupMocks: func(sm *MockSessionManager) {
				sm.On("GetSession", mock.Anything, "", "", "").
					Return(&session.Session{Valid: false}, nil)
			},
			expectedResult: checkResult{is: UNAUTHENTICATED},
		}, {
			name:   "Policy deny",
			cookie: &http.Cookie{Name: "session", Value: ""},
			setupMocks: func(sm *MockSessionManager) {
				sm.On("GetSession", mock.Anything, "", "", "").
					Return(&session.Session{Valid: true}, nil)
			},
			expectedResult: checkResult{is: DENIED},
		}, {
			name:   "Policy deny method",
			cookie: &http.Cookie{Name: "session", Value: ""},
			method: "POST",
			host:   "our.service.com",
			path:   "/foo/bar",
			setupMocks: func(sm *MockSessionManager) {
				sm.On("GetSession", mock.Anything, "", "", "").
					Return(&session.Session{
						Valid:   true,
						Subject: "me",
						Issuer:  "https://127.0.0.1:8443",
					}, nil)
			},
			expectedResult: checkResult{is: DENIED},
		}, {
			name:   "Policy deny host",
			cookie: &http.Cookie{Name: "session", Value: ""},
			method: "GET",
			host:   "my.service.org",
			path:   "/foo/bar",
			setupMocks: func(sm *MockSessionManager) {
				sm.On("GetSession", mock.Anything, "", "", "").
					Return(&session.Session{
						Valid:   true,
						Subject: "me",
						Issuer:  "https://127.0.0.1:8443",
					}, nil)
			},
			expectedResult: checkResult{is: DENIED},
		}, {
			name:   "Policy deny path",
			cookie: &http.Cookie{Name: "session", Value: ""},
			method: "GET",
			host:   "our.service.com",
			path:   "/foo/baz",
			setupMocks: func(sm *MockSessionManager) {
				sm.On("GetSession", mock.Anything, "", "", "").
					Return(&session.Session{
						Valid:   true,
						Subject: "me",
						Issuer:  "https://127.0.0.1:8443",
					}, nil)
			},
			expectedResult: checkResult{is: DENIED},
		}, {
			name:   "Policy allow",
			cookie: &http.Cookie{Name: "session", Value: ""},
			method: "GET",
			host:   "our.service.com",
			path:   "/foo/bar",
			setupMocks: func(sm *MockSessionManager) {
				sm.On("GetSession", mock.Anything, "", "", "").
					Return(&session.Session{
						Valid:   true,
						Subject: "me",
						Issuer:  "https://127.0.0.1:8443",
					}, nil)
			},
			expectedResult: checkResult{is: ALLOWED},
		},
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			ctx := t.Context()

			mockSessionManager := new(MockSessionManager)
			if tc.setupMocks != nil {
				tc.setupMocks(mockSessionManager)
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
				WithSessionManager(mockSessionManager),
				WithPolicyEngine(pe),
				WithClientDataSigner(signer),
			)
			if err != nil {
				t.Fatalf("could not create server: %s", err)
			}

			// Act
			result := srv.checkSession(ctx, tc.cookie, tc.tenantID, tc.fingerprint, tc.method, tc.host, tc.path)

			// Assert
			assert.Equal(t, tc.expectedResult.is, result.is)
			mockSessionManager.AssertExpectations(t)
		})
	}
}
