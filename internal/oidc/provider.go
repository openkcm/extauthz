package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/patrickmn/go-cache"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/extauthz/internal/utils"
)

// ProviderClient is an interface for looking up providers for the issuer.
type ProviderClient interface {
	Get(ctx context.Context, issuer string) (*Provider, error)
}

// Provider represents a specific OIDC provider.
type Provider struct {
	issuerURL     *url.URL
	jwksURL       *url.URL
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
		issuerURL: issuerURL,
		audiences: audiences,
		client:    http.DefaultClient,
		signkeys:  cache.New(30*time.Second, 10*time.Minute),
	}

	for _, opt := range opts {
		err := opt(provider)
		if err != nil {
			return nil, err
		}
	}

	return provider, nil
}
func (p *Provider) IntrospectionEnabled() bool {
	return p.introspectURL != nil
}

// SigningKeyFor returns the key for the given key.
func (p *Provider) SigningKeyFor(ctx context.Context, keyID string) (*jose.JSONWebKey, error) {
	// check the cache first
	key, found := getSigningKey(p.signkeys, keyID)
	if found {
		return key, nil
	}

	slogctx.Debug(ctx, "Signing key cache miss", "keyID", keyID)

	// otherwise fetch the key using the JWKS URI and cache it if found
	if p.jwksURL == nil {
		return nil, errors.New("JWKS endpoint must not be empty")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, p.jwksURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("could not build request to get JWKS: %w", err)
	}

	response, err := p.client.Do(request)
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
	checkedKey, found := lookupValidSigningKey(keyID, &jwks)
	if found {
		storeSigningKey(p.signkeys, keyID, checkedKey)
		return checkedKey, nil
	}

	// return an error if the key was not found
	return nil, fmt.Errorf("could not find key for key ID %s", keyID)
}

type wellKnownOpenIDConfiguration struct {
	Issuer                string `json:"issuer"`
	JWKSURI               string `json:"jwks_uri"`
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"` // optional
}

func (p *Provider) PopulateFromWellKnownOpenIDConfiguration(ctx context.Context) error {
	if utils.CheckAllPopulated(p.jwksURL, p.introspectURL) {
		return nil
	}

	wkoc := wellKnownOpenIDConfiguration{}
	wkocURI := p.issuerURL.JoinPath(".well-known/openid-configuration")

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, wkocURI.String(), nil)
	if err != nil {
		return fmt.Errorf("could not build request to get well known OpenID configuration: %w", err)
	}

	response, err := p.client.Do(request)
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

	p.jwksURL, err = parseEndpoint(wkoc.JWKSURI)
	if err != nil {
		return fmt.Errorf("could not parse JWKS URI: %w", err)
	}

	p.introspectURL, err = parseEndpoint(wkoc.IntrospectionEndpoint)
	if err != nil {
		return fmt.Errorf("could not parse introspection endpoint: %w", err)
	}

	return nil
}

type Introspection struct {
	Active bool `json:"active"` // Required. Indicator of whether the presented token is currently active.
	// Scope     string `json:"scope,omitempty"`      // Optional. Comma-separated list of scope.
	// ClientID  string `json:"client_id,omitempty"`  // Optional. Client identifier.
	// Username  string `json:"username,omitemtpy"`   // Optional. User identifier.
	// TokenType string `json:"token_type,omitempty"` // Optional.
	// Exp       int64  `json:"exp,omitemtpy"`        // Optional. Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token will expire, as defined in JWT [RFC7519].
	// Iat       int64  `json:"iat,omitempty"`        // Optional. Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token was originally issued, as defined in JWT [RFC7519].
	// Nbf       int64  `json:"nbf,omitempty"`        // Optional. Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this token is not to be used before, as defined in JWT [RFC7519].
}

func (p *Provider) introspect(ctx context.Context, bearerToken, introspectToken string) (Introspection, error) {
	if p.introspectURL == nil {
		return Introspection{}, errors.New("introspect endpoint must not be empty")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.introspectURL.String(), nil)
	if err != nil {
		return Introspection{}, fmt.Errorf("creating new http request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	q := req.URL.Query()
	q.Set("token", introspectToken)
	req.URL.RawQuery = q.Encode()

	resp, err := p.client.Do(req)
	if err != nil {
		return Introspection{}, fmt.Errorf("executing http request: %w", err)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	var intr Introspection

	err = json.NewDecoder(resp.Body).Decode(&intr)
	if err != nil {
		return Introspection{}, fmt.Errorf("decoding introspection response: %w", err)
	}

	return intr, nil
}

func parseEndpoint(endpoint string) (*url.URL, error) {
	if endpoint == "" {
		//nolint: nilnil
		return nil, nil
	}
	return url.Parse(endpoint)
}
