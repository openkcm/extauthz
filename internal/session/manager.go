package session

import (
	"context"

	"google.golang.org/grpc"

	sessionv1 "github.com/openkcm/api-sdk/proto/kms/api/cmk/sessionmanager/session/v1"
)

type ManagerOption func(*Manager)

type Manager struct {
	grpcConn   *grpc.ClientConn
	grpcClient sessionv1.ServiceClient
}

func NewManager(grpcConn *grpc.ClientConn, opts ...ManagerOption) (*Manager, error) {
	m := &Manager{
		grpcConn: grpcConn,
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
