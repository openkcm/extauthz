package session

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/openkcm/common-sdk/pkg/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	rpcv1 "github.com/openkcm/api-sdk/proto/kms/api/cmk/rpc/v1"
	sessionv1 "github.com/openkcm/api-sdk/proto/kms/api/cmk/sessionmanager/session/v1"
	typesv1 "github.com/openkcm/api-sdk/proto/kms/api/cmk/types/v1"

	"github.com/openkcm/extauthz/internal/oauth2client"
)

type SessionManagerMock struct {
	sessionv1.UnimplementedServiceServer
	mock.Mock
}

func (m *SessionManagerMock) GetSession(ctx context.Context, req *sessionv1.GetSessionRequest) (*sessionv1.GetSessionResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return &sessionv1.GetSessionResponse{}, args.Error(1)
	}
	//nolint:forcetypeassert
	return args.Get(0).(*sessionv1.GetSessionResponse), args.Error(1)
}

func (m *SessionManagerMock) GetOIDCProvider(ctx context.Context, req *sessionv1.GetOIDCProviderRequest) (*sessionv1.GetOIDCProviderResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return &sessionv1.GetOIDCProviderResponse{}, args.Error(1)
	}
	//nolint:forcetypeassert
	return args.Get(0).(*sessionv1.GetOIDCProviderResponse), args.Error(1)
}

func startMockGRPCServer(t *testing.T) (*grpc.Server, *SessionManagerMock, *bufconn.Listener) {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	sessionManagerMock := new(SessionManagerMock)
	sessionv1.RegisterServiceServer(server, sessionManagerMock)
	go func() {
		_ = server.Serve(lis)
	}()
	return server, sessionManagerMock, lis
}

func setupSessionClient(t *testing.T, opts ...ManagerOption) (*Manager, *SessionManagerMock, func()) {
	t.Helper()
	grpcServer, sessionMock, lis := startMockGRPCServer(t)
	bufDialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}
	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(bufDialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	assert.NoError(t, err)
	manager, err := NewManager(conn, opts...)
	assert.NoError(t, err)
	teardown := func() {
		// manager.Close()
		grpcServer.Stop()
	}
	return manager, sessionMock, teardown
}

func TestNewManager(t *testing.T) {
	t.Run("no panic with nil options", func(t *testing.T) {
		assert.NotPanics(t, func() {
			//nolint:errcheck
			NewManager(nil, nil)
		})
	})
}

func TestGetSession(t *testing.T) {
	// create the test cases
	tests := []struct {
		name       string
		sessionID  string
		tenantID   string
		expected   *Session
		wantErr    bool
		setupMocks func(*SessionManagerMock)
	}{
		{
			name: "valid session",
			setupMocks: func(mss *SessionManagerMock) {
				mss.On("GetSession", mock.Anything, mock.Anything).
					Return(&sessionv1.GetSessionResponse{
						Valid: true,
					}, nil)
			},
			expected: &Session{
				Valid: true,
			},
			wantErr: false,
		}, {
			name: "invalid session",
			setupMocks: func(mss *SessionManagerMock) {
				mss.On("GetSession", mock.Anything, mock.Anything).
					Return(&sessionv1.GetSessionResponse{
						Valid: false,
					}, nil)
			},
			expected: &Session{
				Valid: false,
			},
			wantErr: false,
		}, {
			name: "Tenant blocked violation",
			setupMocks: func(mss *SessionManagerMock) {
				st := status.New(codes.FailedPrecondition, "failed precondition")
				st, _ = st.WithDetails(&rpcv1.PreconditionFailure{
					Violations: []*rpcv1.PreconditionFailure_Violation{{
						Type: violationTenantBlocked,
					}},
				})
				mss.On("GetSession", mock.Anything, mock.Anything).
					Return(nil, st.Err())
			},
			expected: nil,
			wantErr:  true,
		},
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			manager, mock, teardown := setupSessionClient(t)
			defer teardown()
			if tc.setupMocks != nil {
				tc.setupMocks(mock)
			}

			// Act
			got, err := manager.GetSession(t.Context(), tc.sessionID, tc.tenantID)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Manager.GetSession() return an unexpected error %v", err)
			}

			assert.Equal(t, tc.expected, got)
			mock.AssertExpectations(t)
		})
	}
}

func TestManager_GetOIDCProvider(t *testing.T) {
	issuer := "https://example.com/iss"
	audiences := []string{"a", "b"}
	customJWKSURI := "https://example.com/custom/jwks"

	provider, err := oidc.NewProvider(issuer, audiences)
	if err != nil {
		panic(err)
	}
	providerWithJWKS, err := oidc.NewProvider(issuer, audiences, oidc.WithCustomJWKSURI(customJWKSURI))
	if err != nil {
		panic(err)
	}

	tests := []struct {
		name            string
		setupMocks      func(*SessionManagerMock)
		oauth2Builder   oauth2client.Builder
		tenantID        string
		want            *oidc.Provider
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name: "Success",
			setupMocks: func(sm *SessionManagerMock) {
				sm.On("GetOIDCProvider", mock.Anything, mock.Anything).Return(&sessionv1.GetOIDCProviderResponse{
					Provider: &typesv1.OIDCProvider{
						IssuerUrl: issuer,
						Audiences: audiences,
					},
				}, nil)
			},
			tenantID: "tenant-id",
			want:     provider,
			wantErr:  false,
		},
		{
			name: "Error",
			setupMocks: func(sm *SessionManagerMock) {
				sm.On("GetOIDCProvider", mock.Anything, mock.Anything).Return(nil, errors.New("some error"))
			},
			tenantID:        "tenant-id",
			want:            nil,
			wantErr:         true,
			wantErrContains: "executing an rpc request",
		},
		{
			name: "NotFound returns ErrNotFound",
			setupMocks: func(sm *SessionManagerMock) {
				sm.On("GetOIDCProvider", mock.Anything, mock.Anything).
					Return(nil, status.Error(codes.NotFound, "tenant not found"))
			},
			tenantID:  "unknown-tenant",
			want:      nil,
			wantErr:   true,
			wantErrIs: ErrNotFound,
		},
		{
			name: "Success with OAuth2 client builder",
			setupMocks: func(sm *SessionManagerMock) {
				sm.On("GetOIDCProvider", mock.Anything, mock.Anything).Return(&sessionv1.GetOIDCProviderResponse{
					Provider: &typesv1.OIDCProvider{
						IssuerUrl: issuer,
						Audiences: audiences,
						ClientId:  "my-client-id",
					},
				}, nil)
			},
			oauth2Builder: func(_ string) (*http.Client, error) {
				return &http.Client{}, nil
			},
			tenantID: "tenant-id",
			want:     provider,
			wantErr:  false,
		},
		{
			name: "OAuth2 client builder error",
			setupMocks: func(sm *SessionManagerMock) {
				sm.On("GetOIDCProvider", mock.Anything, mock.Anything).Return(&sessionv1.GetOIDCProviderResponse{
					Provider: &typesv1.OIDCProvider{
						IssuerUrl: issuer,
						Audiences: audiences,
						ClientId:  "my-client-id",
					},
				}, nil)
			},
			oauth2Builder: func(_ string) (*http.Client, error) {
				return nil, errors.New("oauth2 client creation failed")
			},
			tenantID:        "tenant-id",
			want:            nil,
			wantErr:         true,
			wantErrContains: "creating OAuth2 HTTP client",
		},
		{
			name: "OAuth2 builder configured but clientID empty",
			setupMocks: func(sm *SessionManagerMock) {
				sm.On("GetOIDCProvider", mock.Anything, mock.Anything).Return(&sessionv1.GetOIDCProviderResponse{
					Provider: &typesv1.OIDCProvider{
						IssuerUrl: issuer,
						Audiences: audiences,
						ClientId:  "", // Empty clientID
					},
				}, nil)
			},
			oauth2Builder: func(_ string) (*http.Client, error) {
				// This should not be called when clientID is empty
				panic("builder should not be called when clientID is empty")
			},
			tenantID: "tenant-id",
			want:     provider,
			wantErr:  false,
		},
		{
			name: "Success with custom JWKS URI",
			setupMocks: func(sm *SessionManagerMock) {
				sm.On("GetOIDCProvider", mock.Anything, mock.Anything).Return(&sessionv1.GetOIDCProviderResponse{
					Provider: &typesv1.OIDCProvider{
						IssuerUrl: issuer,
						Audiences: audiences,
						JwksUri:   customJWKSURI,
					},
				}, nil)
			},
			tenantID: "tenant-id",
			want:     providerWithJWKS,
			wantErr:  false,
		},
		{
			name: "Invalid issuer URL",
			setupMocks: func(sm *SessionManagerMock) {
				sm.On("GetOIDCProvider", mock.Anything, mock.Anything).Return(&sessionv1.GetOIDCProviderResponse{
					Provider: &typesv1.OIDCProvider{
						IssuerUrl: "://invalid-url",
						Audiences: audiences,
					},
				}, nil)
			},
			tenantID:        "tenant-id",
			want:            nil,
			wantErr:         true,
			wantErrContains: "creating a new oidc provider",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var opts []ManagerOption
			if tc.oauth2Builder != nil {
				opts = append(opts, WithOAuth2ClientBuilder(tc.oauth2Builder))
			}
			manager, sessionMock, teardown := setupSessionClient(t, opts...)
			defer teardown()
			if tc.setupMocks != nil {
				tc.setupMocks(sessionMock)
			}

			got, err := manager.GetOIDCProvider(t.Context(), tc.tenantID)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Manager.GetOIDCProvider() return an unexpected error %v", err)
			}

			if tc.wantErrIs != nil {
				assert.ErrorIs(t, err, tc.wantErrIs)
			}
			if tc.wantErrContains != "" && err != nil {
				assert.Contains(t, err.Error(), tc.wantErrContains)
			}

			if diff := cmp.Diff(tc.want, got, cmpopts.IgnoreUnexported(oidc.Provider{})); diff != "" {
				t.Fatalf("Unexpected provider result (-want, +got):\n%s", diff)
			}

			sessionMock.AssertExpectations(t)
		})
	}
}
