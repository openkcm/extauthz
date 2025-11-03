package oidc

import (
	"context"
	"errors"
	"net/url"

	"google.golang.org/grpc"

	oidcproviderv1 "github.com/openkcm/api-sdk/proto/kms/api/cmk/sessionmanager/oidcprovider/v1"
)

type ProviderSource struct {
	grpcConn *grpc.ClientConn
	pclient  oidcproviderv1.ServiceClient
}

var _ ProviderClient = &ProviderSource{}

// ProviderSourceOption is used to configure an OIDC provider source.
type ProviderSourceOption func(*ProviderSource) error

func WithGRPCConn(grpcConn *grpc.ClientConn) ProviderSourceOption {
	return func(client *ProviderSource) error {
		client.grpcConn = grpcConn
		return nil
	}
}

// NewProviderSource creates a new OIDC provider and applies the given options.
func NewProviderSource(opts ...ProviderSourceOption) (*ProviderSource, error) {
	oidcProvider := &ProviderSource{}
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
func (c *ProviderSource) Get(ctx context.Context, issuer string) (*Provider, error) {
	GetOIDCProviderRequest := &oidcproviderv1.GetOIDCProviderRequest{
		Issuer: issuer,
	}
	resp, err := c.pclient.GetOIDCProvider(ctx, GetOIDCProviderRequest)
	if err != nil {
		return nil, err
	}
	issuerURL, err := url.Parse(resp.GetIssuer())
	if err != nil {
		return nil, err
	}
	return NewProvider(issuerURL, resp.GetAudiences(), nil)
}
