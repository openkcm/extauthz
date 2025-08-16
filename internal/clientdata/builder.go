package clientdata

import (
	"github.com/openkcm/common-sdk/pkg/auth"
)

type clientDataBuilder struct {
	auth.ClientData

	factory *Factory
}

type Option func(*clientDataBuilder) error

func WithClientType(val ClientType) Option {
	return func(b *clientDataBuilder) error {
		enrichHeaderWithType := b.factory.featureGates.IsFeatureEnabled(EnrichHeaderWithClientType)
		if enrichHeaderWithType {
			b.ClientData.Type = string(val)
		}
		return nil
	}
}
func WithSubject(val string) Option {
	return func(b *clientDataBuilder) error {
		b.ClientData.Subject = val
		return nil
	}
}
func WithEmail(val string) Option {
	return func(b *clientDataBuilder) error {
		b.ClientData.Email = val
		return nil
	}
}
func WithRegion(val string) Option {
	return func(b *clientDataBuilder) error {
		enrichHeaderWithRegion := b.factory.featureGates.IsFeatureEnabled(EnrichHeaderWithClientRegion)
		if enrichHeaderWithRegion && val != "" {
			b.ClientData.Region = val
		}

		return nil
	}
}
func WithGroups(vals []string) Option {
	return func(b *clientDataBuilder) error {
		b.ClientData.Groups = vals
		return nil
	}
}
func WithSignatureAlgorithm(val auth.SignatureAlgorithm) Option {
	return func(b *clientDataBuilder) error {
		b.ClientData.SignatureAlgorithm = val
		return nil
	}
}
