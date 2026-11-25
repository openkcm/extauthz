package session

import (
	"context"
	"fmt"

	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/openkcm/common-sdk/pkg/commonhttp"
	"github.com/openkcm/common-sdk/pkg/oidc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	rpcv1 "github.com/openkcm/api-sdk/proto/kms/api/cmk/rpc/v1"
	sessionv1 "github.com/openkcm/api-sdk/proto/kms/api/cmk/sessionmanager/session/v1"

	"github.com/openkcm/extauthz/internal/oauth2client"
)

const (
	violationTenantBlocked = "tenant_blocked"
)

type Manager struct {
	grpcConn   *grpc.ClientConn
	grpcClient sessionv1.ServiceClient

	newCreds oauth2client.Builder
}

func NewManager(grpcConn *grpc.ClientConn, opts ...ManagerOption) (*Manager, error) {
	m := &Manager{
		grpcConn:   grpcConn,
		grpcClient: sessionv1.NewServiceClient(grpcConn),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(m)
		}
	}
	return m, nil
}

func (m *Manager) Close() error {
	return m.grpcConn.Close()
}

func (m *Manager) GetSession(ctx context.Context, sessionID, tenantID string) (*Session, error) {
	getSessionRequest := &sessionv1.GetSessionRequest{
		SessionId: sessionID,
		TenantId:  tenantID,
	}
	resp, err := m.grpcClient.GetSession(ctx, getSessionRequest)
	if err != nil {
		st := status.Convert(err)
		for _, d := range st.Details() {
			switch info := d.(type) {
			case *rpcv1.PreconditionFailure:
				for _, violation := range info.GetViolations() {
					switch violation.GetType() {
					case violationTenantBlocked:
						return nil, ErrTenantBlocked
					}
				}
			}
		}

		return nil, err
	}

	sess := &Session{
		Valid:       resp.GetValid(),
		Issuer:      resp.GetIssuer(),
		Subject:     resp.GetSubject(),
		GivenName:   resp.GetGivenName(),
		FamilyName:  resp.GetFamilyName(),
		Email:       resp.GetEmail(),
		Groups:      resp.GetGroups(),
		AuthContext: resp.GetAuthContext(),
	}
	return sess, nil
}

func (m *Manager) GetOIDCProvider(ctx context.Context, tenantID string) (*oidc.Provider, error) {
	pResp, err := m.grpcClient.GetOIDCProvider(ctx, &sessionv1.GetOIDCProviderRequest{TenantId: tenantID})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, ErrNotFound
		}

		return nil, fmt.Errorf("executing an rpc request: %w", err)
	}

	provider := pResp.GetProvider()
	// TODO: we should extend the API to distinguish between:
	// - issuer, which may not be a valid URI but rather a string identifier
	// - issuerURI, which must be a valid URI used for OIDC discovery
	// For now, we assume that the issuer is a valid URI and use it for both fields.
	issuer := provider.GetIssuerUrl()
	clientID := provider.GetClientId()

	opts := make([]oidc.ProviderOption, 0, 2)

	publicHTTPClient, err := commonhttp.NewHTTPClient(&commoncfg.HTTPClient{})
	if err != nil {
		return nil, fmt.Errorf("creating public OIDC HTTP client: %w", err)
	}

	// The builder supplies an instrumented authenticated client when configured.
	httpClient := publicHTTPClient
	if m.newCreds != nil && clientID != "" {
		var err error
		httpClient, err = m.newCreds(clientID)
		if err != nil {
			return nil, fmt.Errorf("creating OAuth2 HTTP client for clientID %s: %w", clientID, err)
		}
	}
	opts = append(opts, oidc.WithPublicHTTPClient(publicHTTPClient), oidc.WithSecureHTTPClient(httpClient))
	if provider.GetJwksUri() != "" {
		opts = append(opts, oidc.WithCustomJWKSURI(provider.GetJwksUri()))
	}

	oidcProvider, err := oidc.NewProvider(issuer, provider.GetAudiences(), opts...)
	if err != nil {
		return nil, fmt.Errorf("creating a new oidc provider: %w", err)
	}

	return oidcProvider, nil
}
