package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/patrickmn/go-cache"

	slogctx "github.com/veqryn/slog-context"
)

var (
	DefaultIssuerClaims = []string{"iss"}
)

// Provider represents a specific OIDC provider.
type Provider struct {
	IssuerURL     *url.URL
	JwksURI       *url.URL
	IntrospectURL *url.URL
	Audiences     []string
	httpClient    *http.Client

	// cache the signing keys by key ID
	signkeys *cache.Cache
}

// ProviderOption is used to configure a provider.
type ProviderOption func(*Provider) error

// WithSigningKeyCacheExpiration configures the expiration of cached signing keys.
// A cach miss will result in a new request to the JWKS URI.
func WithSigningKeyCacheExpiration(expiration, cleanup time.Duration) ProviderOption {
	return func(provider *Provider) error {
		provider.signkeys = cache.New(expiration, cleanup)
		return nil
	}
}

func WithoutCache() ProviderOption {
	return func(provider *Provider) error {
		provider.signkeys = nil
		return nil
	}
}

// WithProviderHTTPClient configures a dedicated http client.
func WithProviderHTTPClient(c *http.Client) ProviderOption {
	return func(provider *Provider) error {
		if c == nil {
			return errors.New("client must not be nil")
		}

		provider.httpClient = c

		return nil
	}
}

// WithCustomJWKSURI configures a custom JWKS URI.
func WithCustomJWKSURI(jwksURI *url.URL) ProviderOption {
	return func(provider *Provider) error {
		if jwksURI == nil {
			return errors.New("jwksURI must not be nil")
		}

		provider.JwksURI = jwksURI

		return nil
	}
}

// WithIntrospectTokenURL configures a token introspection endpoint.
func WithIntrospectTokenURL(introspectURL *url.URL) ProviderOption {
	return func(provider *Provider) error {
		provider.IntrospectURL = introspectURL
		return nil
	}
}

// NewProvider creates a new provider and applies the given options.
func NewProvider(issuerURL *url.URL, audiences []string, opts ...ProviderOption) (*Provider, error) {
	provider := &Provider{
		IssuerURL:  issuerURL,
		Audiences:  audiences,
		httpClient: http.DefaultClient,
		signkeys:   cache.New(30*time.Second, 10*time.Minute),
	}
	if issuerURL != nil {
		provider.IntrospectURL = makeDefaultIntrospectURL(issuerURL)
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		err := opt(provider)
		if err != nil {
			return nil, err
		}
	}

	return provider, nil
}

// SigningKeyFor returns the key for the given key.
func (provider *Provider) SigningKeyFor(ctx context.Context, keyID string) (*jose.JSONWebKey, error) {
	// check the cache first
	if provider.signkeys != nil {
		if keyInterface, found := provider.signkeys.Get(keyID); found {
			if key, ok := keyInterface.(*jose.JSONWebKey); ok {
				return key, nil
			}
		}

		slogctx.Debug(ctx, "Signing key cache miss", "keyID", keyID)
	}

	// otherwise fetch the key using the JWKS URI and cache it if found
	if provider.JwksURI == nil {
		err := provider.getWellKnownOpenIDConfiguraton(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get well known OpenID configuration: %w", err)
		}
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, provider.JwksURI.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("could not build request to get JWKS: %w", err)
	}

	response, err := provider.httpClient.Do(request)
	if err != nil {
		return nil, err
	}

	defer func() {
		err := response.Body.Close()
		if err != nil {
			slogctx.Error(ctx, "could not close response body", "error", err)
		}
	}()

	// decode the jwks
	var jwks jose.JSONWebKeySet

	err = json.NewDecoder(response.Body).Decode(&jwks)
	if err != nil {
		return nil, fmt.Errorf("could not decode jwks: %w", err)
	}

	// find the key for the given key ID, cache it and return it
	for _, k := range jwks.Keys {
		if k.Use == "sig" && k.KeyID == keyID {
			if provider.signkeys != nil {
				// Cache the item. Constant `cache.DefaultExpiration` means
				// that this item does not have a custom expiration, but uses
				// the configured expiration of the cache.
				// https://pkg.go.dev/github.com/patrickmn/go-cache#Cache.Set
				provider.signkeys.Set(keyID, &k, cache.DefaultExpiration)
			}

			return &k, nil
		}
	}

	// return an error if the key was not found
	return nil, fmt.Errorf("could not find key for key ID %s", keyID)
}

type wellKnownOpenIDConfiguration struct {
	Issuer                string `json:"issuer"`
	JWKSURI               string `json:"jwks_uri"`
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"` // optional
}

func (provider *Provider) getWellKnownOpenIDConfiguraton(ctx context.Context) error {
	wkoc := wellKnownOpenIDConfiguration{}
	wkocURI := provider.IssuerURL.JoinPath(".well-known/openid-configuration")

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, wkocURI.String(), nil)
	if err != nil {
		return fmt.Errorf("could not build request to get well known OpenID configuration: %w", err)
	}

	response, err := provider.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("could not get well known OpenID configuration: %w", err)
	}

	defer func() {
		err := response.Body.Close()
		if err != nil {
			slogctx.Error(ctx, "could not close response body", "error", err)
		}
	}()

	// decode the well known OpenID configuration
	err = json.NewDecoder(response.Body).Decode(&wkoc)
	if err != nil {
		return fmt.Errorf("could not decode well known OpenID configuration: %w", err)
	}

	jwksURI, err := url.Parse(wkoc.JWKSURI)
	if err != nil {
		return fmt.Errorf("could not parse JWKS URI: %w", err)
	}

	provider.JwksURI = jwksURI

	// Wellknown configuration may provide a token introspection endpoint.
	if wkoc.IntrospectionEndpoint != "" {
		provider.IntrospectURL, err = url.Parse(wkoc.IntrospectionEndpoint)
		if err != nil {
			return fmt.Errorf("could not parse introspection endpoint: %w", err)
		}
	}

	if provider.IntrospectURL == nil {
		provider.IntrospectURL = makeDefaultIntrospectURL(provider.IssuerURL)
	}

	return nil
}
