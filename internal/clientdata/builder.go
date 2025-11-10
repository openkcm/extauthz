package clientdata

import (
	"github.com/openkcm/common-sdk/pkg/auth"
)

type clientDataBuilder struct {
	auth.ClientData

	signer *Signer
}

type Option func(*clientDataBuilder) error

// Mandatory user attributes

func WithIdentifier(val string) Option {
	return func(b *clientDataBuilder) error {
		b.Identifier = val
		return nil
	}
}
func WithEmail(val string) Option {
	return func(b *clientDataBuilder) error {
		b.Email = val
		return nil
	}
}
func WithGivenName(val string) Option {
	return func(b *clientDataBuilder) error {
		b.GivenName = val
		return nil
	}
}
func WithFamilyName(val string) Option {
	return func(b *clientDataBuilder) error {
		b.FamilyName = val
		return nil
	}
}
func WithGroups(vals []string) Option {
	return func(b *clientDataBuilder) error {
		b.Groups = vals
		return nil
	}
}

// Optional user attributes

func WithClientType(val ClientType) Option {
	return func(b *clientDataBuilder) error {
		enrichHeaderWithType := b.signer.featureGates.IsFeatureEnabled(EnrichHeaderWithClientType)
		if enrichHeaderWithType {
			b.Type = string(val)
		}

		return nil
	}
}
func WithRegion(val string) Option {
	return func(b *clientDataBuilder) error {
		enrichHeaderWithRegion := b.signer.featureGates.IsFeatureEnabled(EnrichHeaderWithClientRegion)
		if enrichHeaderWithRegion && val != "" {
			b.Region = val
		}

		return nil
	}
}

// WithAuthContext specifies the authentication context
// For OIDC this is usually "issuer" and "client_id"
func WithAuthContext(val map[string]string) Option {
	return func(b *clientDataBuilder) error {
		b.AuthContext = val
		return nil
	}
}

// WithSignatureAlgorithm defines the algorithm used to sign the client data
func WithSignatureAlgorithm(val auth.SignatureAlgorithm) Option {
	return func(b *clientDataBuilder) error {
		b.SignatureAlgorithm = val
		return nil
	}
}
