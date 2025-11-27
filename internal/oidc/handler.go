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
	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/patrickmn/go-cache"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/extauthz/internal/flags"
)

const (
	IssuerPrefix     = "issuer_"
	IntrospectPrefix = "introspect_"
)

var (
	DefaultIssuerClaims = []string{"iss"}
)

// Handler tracks the set of identity providers to support multi tenancy.
type Handler struct {
	issuerClaimKeys []string
	staticProviders map[string]*Provider
	featureGates    *commoncfg.FeatureGates

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

// WithStaticProvider registers the given provider.
func WithStaticProvider(provider *Provider) HandlerOption {
	return func(handler *Handler) error {
		if provider == nil {
			return errors.New("provider must not be nil")
		}

		handler.RegisterStaticProvider(provider)

		return nil
	}
}

func WithFeatureGates(fg *commoncfg.FeatureGates) HandlerOption {
	return func(server *Handler) error {
		server.featureGates = fg
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
		staticProviders: make(map[string]*Provider),
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
func (handler *Handler) RegisterStaticProvider(provider *Provider) {
	key := IssuerPrefix + provider.issuerURL.String()
	handler.staticProviders[key] = provider
}

func (handler *Handler) ParseAndValidate(ctx context.Context, rawToken string, userclaims any, useCache bool) error {
	// parse the token - at the moment we only support RS256
	token, err := jwt.ParseSigned(rawToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		slogctx.Error(ctx, "Failed to parse token", "error", err)
		return errors.Join(ErrInvalidToken, err)
	}

	// parse the claims without verification
	claims := make(map[string]any)

	err = token.UnsafeClaimsWithoutVerification(&claims)
	if err != nil {
		slogctx.Error(ctx, "Failed to parse token claims (unsafe)", "error", err)
		return errors.Join(ErrInvalidToken, err)
	}

	// check the issuer to find the right provider
	issuer := extractFromClaims(claims, handler.issuerClaimKeys...)
	if issuer == "" { // in case its empty
		slogctx.Error(ctx, "Missing issuer in token claims")
		return errors.Join(ErrInvalidToken, fmt.Errorf("missing keys %v in token claims", handler.issuerClaimKeys))
	}

	issuerURL, err := url.Parse(issuer)
	if err != nil {
		slogctx.Error(ctx, "Failed to parse issuer URL", "error", err, "issuer", issuer)
		return errors.Join(ErrInvalidToken, err)
	}

	switch issuerURL.Scheme {
	case "https":
		// secure scheme, all good
	case "http":
		// insecure scheme, allowed if the feature gate is enabled
		if !handler.featureGates.IsFeatureEnabled(flags.EnableHttpIssuerScheme) {
			slogctx.Error(ctx, "Invalid issuer scheme", "issuer", issuer)
			return errors.Join(ErrInvalidToken, fmt.Errorf("invalid issuer scheme: %s", issuer))
		}
	default:
		slogctx.Error(ctx, "Invalid issuer scheme", "issuer", issuer)
		return errors.Join(ErrInvalidToken, fmt.Errorf("invalid issuer scheme: %s", issuer))
	}

	// let the handler lookup the identity provider for the issuer host
	provider, err := handler.ProviderFor(ctx, issuer)
	if err != nil {
		slogctx.Error(ctx, "Failed to get provider for issuer", "error", err, "issuer", issuer)
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
	if len(provider.audiences) > 0 {
		err = standardClaims.Validate(jwt.Expected{
			AnyAudience: provider.audiences,
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

// ProviderFor returns the provider for the given issuer.
func (handler *Handler) ProviderFor(_ context.Context, issuer string) (*Provider, error) {
	// check the static providers map
	if provider, ok := handler.staticProviders[IssuerPrefix+issuer]; ok {
		return provider, nil
	}

	return nil, errors.Join(ErrNoProvider, fmt.Errorf("no provider found for issuer %s", issuer))
}

// introspect an access or refresh token.
func (handler *Handler) introspect(ctx context.Context, provider *Provider, introspectToken string, useCache bool) (Introspection, error) {
	if handler.featureGates.IsFeatureEnabled(flags.DisableJWTTokenIntrospection) {
		slogctx.Debug(ctx, "Introspection disabled via feature gate")
		return Introspection{Active: true}, nil
	}

	cacheKey := IntrospectPrefix + introspectToken
	if useCache {
		cache, ok := handler.cache.Get(cacheKey)
		if ok {
			//nolint:forcetypeassert
			return cache.(Introspection), nil
		}
	}

	intr, err := provider.introspect(ctx, introspectToken)
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
