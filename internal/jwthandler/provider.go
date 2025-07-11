package jwthandler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/patrickmn/go-cache"
)

// Provider represents a specific JWT provider.
type Provider struct {
	issuerURL     *url.URL
	jwksURI       *url.URL
	introspectURL *url.URL
	audiences     []string
	client        *http.Client

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

// WithCustomJWKSURI configures a custom JWKS URI.
func WithCustomJWKSURI(jwksURI *url.URL) ProviderOption {
	return func(provider *Provider) error {
		if jwksURI == nil {
			return errors.New("jwksURI must not be nil")
		}
		provider.jwksURI = jwksURI
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

// NewProvider creates a new provider and applies the given options.
func NewProvider(issuerURL *url.URL, audiences []string, opts ...ProviderOption) (*Provider, error) {
	provider := &Provider{
		issuerURL: issuerURL,
		audiences: audiences,
		client:    http.DefaultClient,
		signkeys:  cache.New(30*time.Second, 10*time.Minute),
	}
	if issuerURL != nil {
		provider.introspectURL = makeDefaultIntrospectURL(issuerURL)
	}

	for _, opt := range opts {
		if err := opt(provider); err != nil {
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
		slog.Info("Signing key cache miss", "keyID", keyID)
	}

	// otherwise fetch the key using the JWKS URI and cache it if found
	if provider.jwksURI == nil {
		if err := provider.getWellKnownOpenIDConfiguraton(ctx); err != nil {
			return nil, fmt.Errorf("failed to get well known OpenID configuration: %w", err)
		}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, provider.jwksURI.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("could not build request to get JWKS: %w", err)
	}
	response, err := provider.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			slog.Error("could not close response body", "error", err)
		}
	}()

	// decode the jwks
	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(response.Body).Decode(&jwks); err != nil {
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
	wkocURI := provider.issuerURL.JoinPath(".well-known/openid-configuration")
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, wkocURI.String(), nil)
	if err != nil {
		return fmt.Errorf("could not build request to get well known OpenID configuration: %w", err)
	}
	response, err := provider.client.Do(request)
	if err != nil {
		return fmt.Errorf("could not get well known OpenID configuration: %w", err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			slog.Error("could not close response body", "error", err)
		}
	}()

	// decode the well known OpenID configuration
	if err := json.NewDecoder(response.Body).Decode(&wkoc); err != nil {
		return fmt.Errorf("could not decode well known OpenID configuration: %w", err)
	}

	jwksURI, err := url.Parse(wkoc.JWKSURI)
	if err != nil {
		return fmt.Errorf("could not parse JWKS URI: %w", err)
	}

	provider.jwksURI = jwksURI

	// Wellknown configuration may provide a token introspection endpoint.
	if wkoc.IntrospectionEndpoint != "" {
		provider.introspectURL, err = url.Parse(wkoc.IntrospectionEndpoint)
		if err != nil {
			return fmt.Errorf("could not parse introspection endpoint: %w", err)
		}
	}

	if provider.introspectURL == nil {
		provider.introspectURL = makeDefaultIntrospectURL(provider.issuerURL)
	}

	return nil
}

type introspection struct {
	Active bool `json:"active"` // Required. Indicator of whether the presented token is currently active.
	// Scope     string `json:"scope,omitempty"`      // Optional. Comma-separated list of scope.
	// ClientID  string `json:"client_id,omitempty"`  // Optional. Client identifier.
	// Username  string `json:"username,omitemtpy"`   // Optional. User identifier.
	// TokenType string `json:"token_type,omitempty"` // Optional.
	// Exp       int64  `json:"exp,omitemtpy"`        // Optional. Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token will expire, as defined in JWT [RFC7519].
	// Iat       int64  `json:"iat,omitempty"`        // Optional. Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token was originally issued, as defined in JWT [RFC7519].
	// Nbf       int64  `json:"nbf,omitempty"`        // Optional. Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token is not to be used before, as defined in JWT [RFC7519].
}

func (provider *Provider) introspect(ctx context.Context, rawToken string) (introspection, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.introspectURL.String(), nil)
	if err != nil {
		return introspection{}, fmt.Errorf("creating new http request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+rawToken)
	q := req.URL.Query()
	q.Set("token", rawToken)
	req.URL.RawQuery = q.Encode()

	resp, err := provider.client.Do(req)
	if err != nil {
		return introspection{}, fmt.Errorf("executing http request: %w", err)
	}
	defer resp.Body.Close()

	var intr introspection
	if err := json.NewDecoder(resp.Body).Decode(&intr); err != nil {
		return introspection{}, fmt.Errorf("decoding introspection response: %w", err)
	}

	return intr, nil
}

func makeDefaultIntrospectURL(base *url.URL) *url.URL {
	return base.JoinPath("oauth2", "introspect")
}
