package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/samber/oops"
)

// Provider represents a specific OIDC provider.
type Provider struct {
	issuerURL     *url.URL
	jwksURL       *url.URL
	introspectURL *url.URL
	audiences     []string

	client *http.Client

	// cache the signing keys by key ID
	cacheSignKeys *cache.Cache
}

// ProviderOption is used to configure a provider.
type ProviderOption func(*Provider) error

// WithSigningKeyCacheExpiration configures the expiration of cached signing keys.
// A cach miss will result in a new request to the JWKS URI.
func WithSigningKeyCacheExpiration(expiration, cleanup time.Duration) ProviderOption {
	return func(provider *Provider) error {
		provider.cacheSignKeys = cache.New(expiration, cleanup)
		return nil
	}
}

func WithoutCache() ProviderOption {
	return func(provider *Provider) error {
		provider.cacheSignKeys = nil
		return nil
	}
}

// WithClient configures a dedicated http client.
func WithClient(c *http.Client) ProviderOption {
	return func(provider *Provider) error {
		if c == nil {
			return errors.New("client must not be nil")
		}

		provider.client = c

		return nil
	}
}

// WithJWKSURI configures a custom JWKS URI.
func WithJWKSURI(jwksURI *url.URL) ProviderOption {
	return func(provider *Provider) error {
		if jwksURI == nil {
			return errors.New("jwksURL must not be nil")
		}

		provider.jwksURL = jwksURI

		return nil
	}
}

// WithRawJWKSURI configures a custom JWKS URI.
func WithRawJWKSURI(endpoint string) ProviderOption {
	return func(provider *Provider) error {
		var err error
		provider.jwksURL, err = parseEndpoint(endpoint)
		if err != nil {
			return err
		}

		return nil
	}
}

// WithIntrospectTokenURL configures a token introspection endpoint.
func WithIntrospectTokenURL(introspectURL *url.URL) ProviderOption {
	return func(provider *Provider) error {
		provider.introspectURL = introspectURL
		return nil
	}
}

// WithRawIntrospectTokenURL configures a token introspection endpoint.
func WithRawIntrospectTokenURL(endpoint string) ProviderOption {
	return func(provider *Provider) error {
		var err error
		provider.introspectURL, err = parseEndpoint(endpoint)
		if err != nil {
			return err
		}

		return nil
	}
}

// NewProvider creates a new provider and applies the given options.
func NewProvider(issuerURL *url.URL, audiences []string, opts ...ProviderOption) (*Provider, error) {
	provider := &Provider{
		issuerURL:     issuerURL,
		audiences:     audiences,
		client:        http.DefaultClient,
		cacheSignKeys: cache.New(30*time.Second, 10*time.Minute),
	}

	for _, opt := range opts {
		err := opt(provider)
		if err != nil {
			return nil, err
		}
	}

	return provider, nil
}

func (p *Provider) RefreshConfiguration(ctx context.Context) error {
	err := p.extractDataFromWellKnownConfiguration(ctx)
	if err != nil {
		return oops.Hint("failed to extract information from ../.well-known/openid-configuration endpoint").Wrap(err)
	}

	return nil
}

func (p *Provider) hasIntrospectionEnabled() bool {
	return p.introspectURL != nil
}

func parseEndpoint(endpoint string) (*url.URL, error) {
	if endpoint == "" {
		//nolint: nilnil
		return nil, nil
	}
	return url.Parse(endpoint)
}
