package jwthandler

import (
	"context"
	"errors"

	"google.golang.org/grpc"
)

type ProviderSource struct {
	grpcConn *grpc.ClientConn
}

var _ ProviderClient = &ProviderSource{}

// ProviderSourceOption is used to configure an JWT provider source.
type ProviderSourceOption func(*ProviderSource) error

func WithGRPCConn(grpcConn *grpc.ClientConn) ProviderSourceOption {
	return func(client *ProviderSource) error {
		client.grpcConn = grpcConn
		return nil
	}
}

// NewProviderSource creates a new JWT provider and applies the given options.
func NewProviderSource(opts ...ProviderSourceOption) (*ProviderSource, error) {
	oidcProvider := &ProviderSource{}
	for _, opt := range opts {
		err := opt(oidcProvider)
		if err != nil {
			return nil, err
		}
	}
	return oidcProvider, nil
}

func (c *ProviderSource) Get(ctx context.Context, issuer string) (*Provider, error) {
	// TODO: https://github.tools.sap/kms/architecture/blob/add/sessionmanagement/ADD/cmk_session_management.md
	return nil, errors.New("not implemented")
}
