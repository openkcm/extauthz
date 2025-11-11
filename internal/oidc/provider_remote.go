package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/openkcm/common-sdk/pkg/commongrpc"
	"google.golang.org/grpc"

	oidcproviderv1 "github.com/openkcm/api-sdk/proto/kms/api/cmk/sessionmanager/oidcprovider/v1"
)

// RemoteProvider is an interface for looking up providers for the issuer.
type RemoteProvider interface {
	Get(ctx context.Context, issuer string) (*Provider, error)
}

type remoteProviderInternal struct {
	grpcConn *grpc.ClientConn
	pclient  oidcproviderv1.ServiceClient
}

var _ RemoteProvider = &remoteProviderInternal{}

// RemoteProviderOption is used to configure an reote OIDC provider.
type RemoteProviderOption func(*remoteProviderInternal) error

func WithGRPCConn(grpcConn *grpc.ClientConn) RemoteProviderOption {
	return func(client *remoteProviderInternal) error {
		client.grpcConn = grpcConn
		return nil
	}
}

func WithGRPCClientConfiguration(cfg *commoncfg.GRPCClient) RemoteProviderOption {
	return func(client *remoteProviderInternal) error {
		grpcConn, err := commongrpc.NewClient(cfg)
		if err != nil {
			return fmt.Errorf("failed to create gRPC connection to remote oidc provider: %w", err)
		}
		client.grpcConn = grpcConn
		return nil
	}
}

// NewExternalProvider creates a new OIDC provider and applies the given options.
func NewExternalProvider(opts ...RemoteProviderOption) (RemoteProvider, error) {
	oidcProvider := &remoteProviderInternal{}

	for _, opt := range opts {
		err := opt(oidcProvider)
		if err != nil {
			return nil, err
		}
	}

	if oidcProvider.grpcConn == nil {
		return nil, errors.New("grpc connection is required")
	}

	oidcProvider.pclient = oidcproviderv1.NewServiceClient(oidcProvider.grpcConn)

	return oidcProvider, nil
}

// Get creates a new provider from the given issuer by calling the OIDC provider
// gRPC service of the Session Manager.
func (c *remoteProviderInternal) Get(ctx context.Context, issuer string) (*Provider, error) {
	resp, err := c.pclient.GetOIDCProvider(ctx, &oidcproviderv1.GetOIDCProviderRequest{
		Issuer: issuer,
	})
	if err != nil {
		return nil, err
	}

	issuerURL, err := url.Parse(resp.GetIssuer())
	if err != nil {
		return nil, err
	}

	oidcProvider, err := NewProvider(issuerURL, resp.GetAudiences())
	if err != nil {
		return nil, fmt.Errorf("error creating oidc provider: %w", err)
	}

	err = oidcProvider.RefreshConfiguration(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh the provider configuration: %w", err)
	}
	return oidcProvider, nil
}
