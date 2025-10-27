// Package oidc implements OIDC token handling in a multi-tenant environment.
// For this a Handler is created, which holds the Providers for validating tokens.
// You can either register providers in a static manner, or inject a client to
// query providers during runtime.
package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/patrickmn/go-cache"

	slogctx "github.com/veqryn/slog-context"
)

var (
	DefaultIssuerClaims = []string{"iss"}
)

// ProviderClient is an interface for looking up providers for the issuer.
type ProviderClient interface {
	Get(ctx context.Context, issuer string) (*Provider, error)
}

// Handler tracks the set of identity providers to support multi tenancy.
type Handler struct {
	issuerClaimKeys []string
	providerClient  ProviderClient

	// cache the providers by issuer
	cache           *cache.Cache // map[string]*Provider or introspection
	expiration      time.Duration
	cleanupInterval time.Duration
}

// HandlerOption is used to configure a handler.
type HandlerOption func(*Handler) error

// WithIssuerClaimKeys configures the behavior of a certain provider.
func WithIssuerClaimKeys(issuerClaimKeys ...string) HandlerOption {
	return func(handler *Handler) error {
		handler.issuerClaimKeys = issuerClaimKeys
		return nil
	}
}

// WithProvider registers the given provider.
func WithProvider(provider *Provider) HandlerOption {
	return func(handler *Handler) error {
		if provider == nil {
			return errors.New("provider must not be nil")
		}

		handler.RegisterProvider(provider)

		return nil
	}
}

func WithProviderClient(providerClient ProviderClient) HandlerOption {
	return func(handler *Handler) error {
		handler.providerClient = providerClient
		handler.cache = cache.New(handler.expiration, handler.cleanupInterval)

		return nil
	}
}

// WithProviderCacheExpiration configures the expiration of cached providers.
func WithProviderCacheExpiration(expiration, cleanup time.Duration) HandlerOption {
	return func(handler *Handler) error {
		handler.expiration = expiration
		handler.cleanupInterval = cleanup
		handler.cache = cache.New(expiration, cleanup)

		return nil
	}
}

// NewHandler creates a new handler and applies the given options.
func NewHandler(opts ...HandlerOption) (*Handler, error) {
	handler := &Handler{
		issuerClaimKeys: DefaultIssuerClaims,
		cache:           cache.New(30*time.Second, 10*time.Minute),
	}
	for _, opt := range opts {
		err := opt(handler)
		if err != nil {
			return nil, err
		}
	}

	return handler, nil
}

// RegisterProvider registers a provider with the handler.
func (handler *Handler) RegisterProvider(provider *Provider) {
	handler.cache.Set(provider.issuerURL.Host, provider, cache.DefaultExpiration)
}

func (handler *Handler) ParseAndValidate(ctx context.Context, rawToken string, userclaims any, allowIntrospectCache bool) error {
	// parse the token - at the moment we only support RS256
	token, err := jwt.ParseSigned(rawToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return errors.Join(ErrInvalidToken, err)
	}

	// parse the claims without verification
	claims := make(map[string]any)

	err = token.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		return errors.Join(ErrInvalidToken, err)
	}

	// check the issuer to find the right provider
	issuer := extractFromClaims(claims, handler.issuerClaimKeys...)
	if issuer == "" { // in case its empty
		return errors.Join(ErrInvalidToken, fmt.Errorf("missing keys %v in token claims", handler.issuerClaimKeys))
	}

	issuerURL, err := url.Parse(issuer)
	if err != nil {
		return errors.Join(ErrInvalidToken, err)
	}

	if issuerURL.Scheme != "https" {
		return errors.Join(ErrInvalidToken, fmt.Errorf("invalid issuer scheme %s", issuerURL.Scheme))
	}

	// let the handler lookup the identity provider for the issuer host
	provider, err := handler.ProviderFor(ctx, issuerURL.Host)
	if err != nil {
		return errors.Join(ErrNoProvider, err)
	}

	// read the key ID from the token headers
	// Not sure why there are multiple headers, take the first one with key ID
	var keyID string

	for _, header := range token.Headers {
		if header.KeyID != "" {
			keyID = header.KeyID
			break
		}
	}

	if keyID == "" {
		return errors.Join(ErrInvalidToken, errors.New("missing kid in token header"))
	}

	// let the provider lookup the key for the key ID
	key, err := provider.SigningKeyFor(ctx, keyID)
	if err != nil {
		return errors.Join(ErrInvalidToken, err)
	}

	// check the signature and read the claims
	standardClaims := jwt.Claims{}

	err = token.Claims(*key, &standardClaims, userclaims)
	if err != nil {
		return errors.Join(ErrInvalidToken, err)
	}

	// verify the expiry and not before
	if standardClaims.Expiry == nil {
		return errors.Join(ErrInvalidToken, errors.New("missing exp in token claims"))
	}

	err = standardClaims.Validate(jwt.Expected{
		Time: time.Now(),
	})
	if err != nil {
		return errors.Join(ErrInvalidToken, err)
	}

	// verify the audience if any
	if len(provider.audiences) > 0 {
		err = standardClaims.Validate(jwt.Expected{
			AnyAudience: provider.audiences,
		})
		if err != nil {
			return errors.Join(ErrInvalidToken, err)
		}
	}

	// Verify if token is not revoked
	intr, err := handler.introspect(ctx, provider, rawToken, rawToken, allowIntrospectCache)
	if err != nil {
		return fmt.Errorf("introspecting token: %w", err)
	}

	if !intr.Active {
		return ErrInvalidToken
	}

	return nil
}

// ProviderFor returns the provider for the given issuer. It either looks up the
// provider in the internal cache or queries the provider client.
func (handler *Handler) ProviderFor(ctx context.Context, issuer string) (*Provider, error) {
	// check the cache first
	if providerInterface, found := handler.cache.Get(issuer); found {
		if key, ok := providerInterface.(*Provider); ok {
			return key, nil
		}
	}

	slogctx.Info(ctx, "Provider cache miss", "issuer", issuer)

	// if we have a provider client, use it to get the provider
	if handler.providerClient != nil {
		p, err := handler.providerClient.Get(ctx, issuer)
		if err != nil {
			return nil, err
		}
		// Cache the item. Constant `cache.DefaultExpiration` means
		// that this item does not have a custom expiration, but uses
		// the configured expiration of the cache.
		// https://pkg.go.dev/github.com/patrickmn/go-cache#Cache.Set
		handler.cache.Set(issuer, p, cache.DefaultExpiration)

		return p, nil
	}

	return nil, errors.Join(ErrNoProvider, fmt.Errorf("no provider found for issuer %s", issuer))
}

// Introspect an access or refresh token with the given issuer.
func (handler *Handler) Introspect(ctx context.Context, issuer, bearerToken, introspectToken string, allowCache bool) (Introspection, error) {
	// parse the issuer URL
	issuerURL, err := url.Parse(issuer)
	if err != nil {
		return Introspection{}, err
	}

	if issuerURL.Scheme != "https" {
		return Introspection{}, fmt.Errorf("invalid issuer scheme %s", issuerURL.Scheme)
	}

	// let the handler lookup the identity provider for the issuer host
	provider, err := handler.ProviderFor(ctx, issuerURL.Host)
	if err != nil {
		return Introspection{}, err
	}

	// let the handler introspect the token
	return handler.introspect(ctx, provider, bearerToken, introspectToken, allowCache)
}

// introspect an access or refresh token.
func (handler *Handler) introspect(ctx context.Context, provider *Provider, bearerToken, introspectToken string, allowCache bool) (Introspection, error) {
	cacheKey := "introspect_" + introspectToken
	if allowCache {
		cache, ok := handler.cache.Get(cacheKey)
		if ok {
			//nolint:forcetypeassert
			return cache.(Introspection), nil
		}
	}

	intr, err := provider.introspect(ctx, bearerToken, introspectToken)
	if err != nil {
		return intr, fmt.Errorf("introspecting token: %w", err)
	}

	handler.cache.Set(cacheKey, intr, 0)

	return intr, nil
}

func extractFromClaims(claims map[string]any, keys ...string) string {
	for _, key := range keys {
		if val, exists := claims[key]; exists {
			if str, ok := val.(string); ok {
				return str
			}
		}
	}

	return ""
}
