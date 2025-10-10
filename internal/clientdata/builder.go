package clientdata

import (
	"github.com/openkcm/common-sdk/pkg/auth"
)

type clientDataBuilder struct {
	auth.ClientData

	signer *Signer
}

type Option func(*clientDataBuilder) error

func WithClientType(val ClientType) Option {
	return func(b *clientDataBuilder) error {
		enrichHeaderWithType := b.signer.featureGates.IsFeatureEnabled(EnrichHeaderWithClientType)
		if enrichHeaderWithType {
			b.Type = string(val)
		}

		return nil
	}
}
func WithSubject(val string) Option {
	return func(b *clientDataBuilder) error {
		b.Subject = val
		return nil
	}
}
func WithEmail(val string) Option {
	return func(b *clientDataBuilder) error {
		b.Email = val
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
func WithIssuer(val string) Option {
	return func(b *clientDataBuilder) error {
		b.Issuer = val
		return nil
	}
}
func WithGroups(vals []string) Option {
	return func(b *clientDataBuilder) error {
		b.Groups = vals
		return nil
	}
}
func WithSignatureAlgorithm(val auth.SignatureAlgorithm) Option {
	return func(b *clientDataBuilder) error {
		b.SignatureAlgorithm = val
		return nil
	}
}
