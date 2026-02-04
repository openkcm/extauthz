package session

import (
	"context"
	"fmt"
	"net/url"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sessionv1 "github.com/openkcm/api-sdk/proto/kms/api/cmk/sessionmanager/session/v1"

	"github.com/openkcm/extauthz/internal/oidc"
)

type ManagerOption func(*Manager)

type Manager struct {
	grpcConn   *grpc.ClientConn
	grpcClient sessionv1.ServiceClient
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

func (m *Manager) GetSession(ctx context.Context, sessionID, tenantID, fingerprint string) (*Session, error) {
	getSessionRequest := &sessionv1.GetSessionRequest{
		SessionId:   sessionID,
		TenantId:    tenantID,
		Fingerprint: fingerprint,
	}
	resp, err := m.grpcClient.GetSession(ctx, getSessionRequest)
	if err != nil {
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

	opts := make([]oidc.ProviderOption, 0, 1)

	provider := pResp.GetProvider()

	issuerURL, err := url.Parse(provider.GetIssuerUrl())
	if err != nil {
		return nil, fmt.Errorf("parsing issuer url from the rpc response: %w", err)
	}

	if u := provider.GetJwksUri(); u != "" {
		jwksURI, err := url.Parse(provider.GetJwksUri())
		if err != nil {
			return nil, fmt.Errorf("parsing jwks uri from the rpc response: %w", err)
		}

		opts = append(opts, oidc.WithCustomJWKSURI(jwksURI))
	}

	oidcProvider, err := oidc.NewProvider(issuerURL, provider.GetAudiences(), opts...)
	if err != nil {
		return nil, fmt.Errorf("creating a new oidc provider: %w", err)
	}

	return oidcProvider, nil
}
