package handler

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/patrickmn/go-cache"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/extauthz/internal/flags"
	"github.com/openkcm/extauthz/internal/oidc"
	"github.com/openkcm/extauthz/internal/session"
)

const (
	introspectPrefix = "introspect_"
)

// OIDC tracks the set of identity providers to support multi tenancy.
type OIDC struct {
	issuerClaimKeys []string
	staticProviders map[string]*oidc.Provider
	featureGates    *commoncfg.FeatureGates
	sessionManager  *session.Manager

	// cache the providers by issuer
	cache           *cache.Cache // map[string]*Provider or introspection
	expiration      time.Duration
	cleanupInterval time.Duration
}

// OIDCOption is used to configure a handler.
type OIDCOption func(*OIDC) error

func WithSessionManager(sm *session.Manager) OIDCOption {
	return func(handler *OIDC) error {
		handler.sessionManager = sm
		return nil
	}
}

// WithIssuerClaimKeys configures the behavior of a certain provider.
func WithIssuerClaimKeys(issuerClaimKeys ...string) OIDCOption {
	return func(handler *OIDC) error {
		handler.issuerClaimKeys = issuerClaimKeys
		return nil
	}
}

// WithStaticProvider registers the given provider.
func WithStaticProvider(provider *oidc.Provider) OIDCOption {
	return func(handler *OIDC) error {
		if provider == nil {
			return errors.New("provider must not be nil")
		}

		handler.RegisterStaticProvider(provider)

		return nil
	}
}

func WithFeatureGates(fg *commoncfg.FeatureGates) OIDCOption {
	return func(server *OIDC) error {
		server.featureGates = fg
		return nil
	}
}

// WithProviderCacheExpiration configures the expiration of cached providers.
func WithProviderCacheExpiration(expiration, cleanup time.Duration) OIDCOption {
	return func(handler *OIDC) error {
		handler.expiration = expiration
		handler.cleanupInterval = cleanup
		handler.cache = cache.New(expiration, cleanup)

		return nil
	}
}

// NewOIDC creates a new handler and applies the given options.
func NewOIDC(opts ...OIDCOption) (*OIDC, error) {
	handler := &OIDC{
		issuerClaimKeys: oidc.DefaultIssuerClaims,
		cache:           cache.New(30*time.Second, 10*time.Minute),
		staticProviders: make(map[string]*oidc.Provider),
		featureGates:    &commoncfg.FeatureGates{},
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		err := opt(handler)
		if err != nil {
			return nil, err
		}
	}

	return handler, nil
}

// RegisterStaticProvider registers a provider with the handler.
func (handler *OIDC) RegisterStaticProvider(provider *oidc.Provider) {
	// To support multiple providers with the same issuer but different JWKS URIs,
	// we prefer to use a custom JWKS URI as the unique key in the static providers
	// map over the potentially non-unique issuer.
	if provider.JwksURI != nil {
		handler.staticProviders[provider.JwksURI.String()] = provider
	} else {
		handler.staticProviders[provider.IssuerURL.String()] = provider
	}
}

func (handler *OIDC) ParseAndValidate(ctx context.Context, rawToken, tenantID string, userclaims any, useCache bool) error {
	// parse the token - at the moment we only support RS256
	token, err := jwt.ParseSigned(rawToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		slogctx.Error(ctx, "Failed to parse token", "error", err)
		return errors.Join(ErrInvalidToken, err)
	}

	// Technically a JWT can have multiple headers, but in practice we expect only one.
	if len(token.Headers) != 1 {
		slogctx.Error(ctx, "Token does not have exactly one header", "headerCount", len(token.Headers))
		return errors.Join(ErrInvalidToken, errors.New("token must have exactly one header"))
	}
	header := token.Headers[0]

	// parse the claims without verification
	claims := make(map[string]any)

	err = token.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		slogctx.Error(ctx, "Failed to parse token claims (unsafe)", "error", err)
		return errors.Join(ErrInvalidToken, err)
	}

	// Check the `jku` header and issuer claim to find the right provider.
	// The issuer may not be unique, so we also use the `jku` header to find the right provider.
	// If the `jku` header is missing, we fallback to using the issuer claim only.
	jwksURI, ok := header.ExtraHeaders["jku"].(string)
	if !ok {
		jwksURI = ""
	}
	issuer := extractFromClaims(claims, handler.issuerClaimKeys...)
	if issuer == "" { // in case its empty
		slogctx.Error(ctx, "Missing issuer in token claims")
		return errors.Join(ErrInvalidToken, fmt.Errorf("missing keys %v in token claims", handler.issuerClaimKeys))
	}

	// Ensure that either jwksURI (if present) or the issuer (as fallback)
	// is a valid https URL.
	urlToCheck := jwksURI
	if urlToCheck == "" {
		urlToCheck = issuer
	}
	parsedURL, err := url.Parse(urlToCheck)
	if err != nil {
		slogctx.Error(ctx, "Failed to parse URL", "error", err, "url", urlToCheck)
		return errors.Join(ErrInvalidToken, err)
	}
	if parsedURL.Scheme != "https" {
		slogctx.Error(ctx, "Invalid URL scheme", "url", urlToCheck)
		return errors.Join(ErrInvalidToken, fmt.Errorf("invalid URL scheme: %s", urlToCheck))
	}

	// let the handler lookup the identity provider for the issuer host
	provider, err := handler.ProviderFor(ctx, issuer, jwksURI, tenantID)
	if err != nil {
		slogctx.Error(ctx, "Failed to get provider for issuer", "error", err, "issuer", issuer, "jwksURI", jwksURI, "tenantID", tenantID)
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
		slogctx.Error(ctx, "Missing kid in token header")
		return errors.Join(ErrInvalidToken, errors.New("missing kid in token header"))
	}

	// let the provider lookup the key for the key ID
	key, err := provider.SigningKeyFor(ctx, keyID)
	if err != nil {
		slogctx.Error(ctx, "Failed to get signing key for token", "error", err, "kid", keyID)
		return errors.Join(ErrInvalidToken, err)
	}

	// check the signature and read the claims
	standardClaims := jwt.Claims{}

	err = token.Claims(*key, &standardClaims, userclaims)
	if err != nil {
		slogctx.Error(ctx, "Failed to verify and deserialize token into claims", "error", err)
		return errors.Join(ErrInvalidToken, err)
	}

	// verify the expiry and not before
	if standardClaims.Expiry == nil {
		slogctx.Error(ctx, "Missing exp in token claims")
		return errors.Join(ErrInvalidToken, errors.New("missing exp in token claims"))
	}

	err = standardClaims.Validate(jwt.Expected{
		Time: time.Now(),
	})
	if err != nil {
		slogctx.Error(ctx, "Failed to validate token claims", "error", err)
		return errors.Join(ErrInvalidToken, err)
	}

	// verify the audience if any
	if len(provider.Audiences) > 0 {
		err = standardClaims.Validate(jwt.Expected{
			AnyAudience: provider.Audiences,
		})
		if err != nil {
			slogctx.Error(ctx, "Failed to validate token audience", "error", err)
			return errors.Join(ErrInvalidToken, err)
		}
	}

	// Verify if token is not revoked
	intr, err := handler.introspect(ctx, provider, rawToken, useCache)
	if err != nil {
		slogctx.Error(ctx, "Failed to introspect token", "error", err)
		return fmt.Errorf("introspecting token: %w", err)
	}

	if !intr.Active {
		slogctx.Error(ctx, "Token is not active")
		return ErrInvalidToken
	}

	return nil
}

// ProviderFor returns the provider for the given issuer/jwksURI.
func (handler *OIDC) ProviderFor(ctx context.Context, issuer, jwksURI, tenantID string) (*oidc.Provider, error) {
	// First check for the unique jwksURI in the static providers map, if any.
	// Otherwise, check for the issuer in the static providers map.
	// This allows supporting multiple providers with the same issuer but different JWKS URIs.
	if jwksURI != "" {
		if provider, ok := handler.staticProviders[jwksURI]; ok {
			if provider.IssuerURL.String() == issuer {
				return provider, nil
			}
		}
	}
	if provider, ok := handler.staticProviders[issuer]; ok {
		return provider, nil
	}

	if handler.sessionManager == nil {
		return nil, fmt.Errorf("%w: no provider found for the issuer %s", ErrNoProvider, issuer)
	}

	provider, err := handler.sessionManager.GetOIDCProvider(ctx, tenantID)
	if err != nil {
		if errors.Is(err, session.ErrNotFound) {
			return nil, fmt.Errorf("%w: no provider found for the issuer %s", ErrNoProvider, issuer)
		}

		return nil, fmt.Errorf("getting provider by tenant id: %w", err)
	}

	return provider, nil
}

// introspect an access or refresh token.
func (handler *OIDC) introspect(ctx context.Context, provider *oidc.Provider, introspectToken string, useCache bool) (oidc.Introspection, error) {
	if handler.featureGates.IsFeatureEnabled(flags.DisableJWTTokenIntrospection) {
		slogctx.Debug(ctx, "Introspection disabled via feature gate")
		return oidc.Introspection{Active: true}, nil
	}

	cacheKey := introspectPrefix + introspectToken
	if useCache {
		cache, ok := handler.cache.Get(cacheKey)
		if ok {
			//nolint:forcetypeassert
			return cache.(oidc.Introspection), nil
		}
	}

	intr, err := provider.Introspect(ctx, introspectToken)
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
