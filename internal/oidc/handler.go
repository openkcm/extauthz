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
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/patrickmn/go-cache"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/extauthz/internal/config"
	"github.com/openkcm/extauthz/internal/flags"
)

var (
	DefaultIssuerClaims = []string{"iss"}
)

// Handler tracks the set of identity providers to support multi tenancy.
type Handler struct {
	started bool
	done    chan struct{}

	mu             sync.RWMutex
	providers      map[string]*Provider
	providerClient ProviderClient

	issuerClaimKeys   []string
	k8sJWTProviderRef *config.K8SProviderRef
	featureGates      *commoncfg.FeatureGates

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

		handler.registerProvider(provider)

		return nil
	}
}

// WithK8SJWTProviderRef registering the K8SProviderRef
func WithK8SJWTProviderRef(k8sJWTProviderRef *config.K8SProviderRef) HandlerOption {
	return func(handler *Handler) error {
		handler.k8sJWTProviderRef = k8sJWTProviderRef
		return nil
	}
}

func WithProviderClient(providerClient ProviderClient) HandlerOption {
	return func(handler *Handler) error {
		handler.providerClient = providerClient

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

		return nil
	}
}

// NewHandler creates a new handler and applies the given options.
func NewHandler(opts ...HandlerOption) (*Handler, error) {
	handler := &Handler{
		issuerClaimKeys: DefaultIssuerClaims,
		featureGates:    &commoncfg.FeatureGates{},

		mu:              sync.RWMutex{},
		expiration:      30 * time.Second,
		cleanupInterval: 10 * time.Minute,

		providers: make(map[string]*Provider),
	}
	for _, opt := range opts {
		err := opt(handler)
		if err != nil {
			return nil, err
		}
	}

	handler.cache = cache.New(handler.expiration, handler.cleanupInterval)

	return handler, nil
}

func (h *Handler) ValidateToken(ctx context.Context, rawToken string, userclaims any, useCache bool) error {
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
	issuer := extractFromClaims(claims, h.issuerClaimKeys...)
	if issuer == "" { // in case its empty
		slogctx.Error(ctx, "Missing issuer in token claims")
		return errors.Join(ErrInvalidToken, fmt.Errorf("missing keys %v in token claims", h.issuerClaimKeys))
	}

	issuerURL, err := url.Parse(issuer)
	if err != nil {
		slogctx.Error(ctx, "Failed to parse issuer URL", "error", err, "issuer", issuer)
		return errors.Join(ErrInvalidToken, err)
	}

	if issuerURL.Scheme != "https" {
		slogctx.Error(ctx, "Invalid issuer scheme", "scheme", issuerURL.Scheme)
		return errors.Join(ErrInvalidToken, fmt.Errorf("invalid issuer scheme %s", issuerURL.Scheme))
	}

	// let the h lookup the identity provider for the issuer host
	provider, err := h.lookupProviderByIssuer(ctx, issuerURL.Host)
	if err != nil {
		slogctx.Error(ctx, "Failed to get provider for issuer", "error", err, "issuer", issuerURL.Host)
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
	key, err := provider.lookupSigningKey(ctx, keyID)
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
	intr, err := h.introspect(ctx, provider, rawToken, rawToken, useCache)
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

// IntrospectToken an access or refresh token with the given issuer.
func (h *Handler) IntrospectToken(ctx context.Context, issuer, bearerToken, introspectToken string, useCache bool) (Introspection, error) {
	// parse the issuer URL
	issuerURL, err := url.Parse(issuer)
	if err != nil {
		return Introspection{}, err
	}

	if issuerURL.Scheme != "https" {
		return Introspection{}, fmt.Errorf("invalid issuer scheme %s", issuerURL.Scheme)
	}

	// let the h lookup the identity provider for the issuer host
	provider, err := h.lookupProviderByIssuer(ctx, issuerURL.Host)
	if err != nil {
		return Introspection{}, err
	}

	// Verify if token is not revoked
	return h.introspect(ctx, provider, bearerToken, introspectToken, useCache)
}

func (h *Handler) IsStarted() bool {
	return h.started
}

// Start starts any internal processes required by the server.
func (h *Handler) Start() error {
	if h.IsStarted() {
		return nil
	}

	defer func() {
		h.started = true
	}()

	h.done = make(chan struct{})

	if h.k8sJWTProviderRef != nil {
		go func() {
			err := h.startK8SProviderWatcher(h.done, h.k8sJWTProviderRef)
			if err != nil {
				slogctx.Error(context.Background(), "Failed to start k8s provider watcher", "error", err)
			}
		}()
	}

	return nil
}

// Close starts any internal processes required by the server.
func (h *Handler) Close() error {
	if !h.IsStarted() {
		return nil
	}

	h.started = false
	close(h.done)
	return nil
}

// lookupProviderByIssuer returns the provider for the given issuer. It either looks up the
// provider in the internal cache or queries the provider client.
func (h *Handler) lookupProviderByIssuer(ctx context.Context, issuer string) (*Provider, error) {
	// check the static providers first
	if provider, ok := h.providers[issuer]; ok {
		return provider, nil
	}

	slogctx.Info(ctx, "Issuer not found in the static provider list", "issuer", issuer)

	// check the cache then
	if providerInterface, found := h.cache.Get(issuer); found {
		if key, ok := providerInterface.(*Provider); ok {
			return key, nil
		}
	}

	slogctx.Info(ctx, "Issuer not found in the provider cache", "issuer", issuer)

	// if we have a provider client, use it to get the provider
	if h.providerClient != nil {
		p, err := h.providerClient.Get(ctx, issuer)
		if err != nil {
			return nil, err
		}
		// Cache the item. Constant `cache.DefaultExpiration` means
		// that this item does not have a custom expiration, but uses
		// the configured expiration of the cache.
		// https://pkg.go.dev/github.com/patrickmn/go-cache#Cache.Set
		h.cache.Set(issuer, p, cache.DefaultExpiration)

		return p, nil
	}

	return nil, errors.Join(ErrNoProvider, fmt.Errorf("no provider found for issuer %s", issuer))
}

// registerProvider registers a provider with the handler.
func (h *Handler) registerProvider(provider *Provider) {
	h.mu.Lock()
	defer h.mu.Unlock()

	issuer := provider.issuerURL.Host
	h.providers[issuer] = provider
}

// swapProvider swap providers with same key with the handler.
func (h *Handler) swapProvider(oldProv *Provider, newProv *Provider) {
	h.mu.Lock()
	defer h.mu.Unlock()

	delete(h.providers, oldProv.issuerURL.Host)
	h.providers[newProv.issuerURL.Host] = newProv
}

// unRegisterProvider remove a provider from the handler.
func (h *Handler) unRegisterProvider(provider *Provider) {
	h.mu.Lock()
	defer h.mu.Unlock()

	issuer := provider.issuerURL.Host
	delete(h.providers, issuer)
}

// introspect an access or refresh token.
func (h *Handler) introspect(ctx context.Context, provider *Provider, bearerToken, introspectToken string, useCache bool) (Introspection, error) {
	introspectionDisabled := h.featureGates.IsFeatureEnabled(flags.DisableJWTTokenIntrospection) ||
		!provider.hasIntrospectionEnabled()
	if introspectionDisabled {
		return Introspection{Active: true}, nil
	}

	cacheKey := "introspect_" + introspectToken
	if useCache {
		value, ok := h.cache.Get(cacheKey)
		if ok {
			//nolint:forcetypeassert
			return value.(Introspection), nil
		}
	}

	intr, err := provider.introspect(ctx, bearerToken, introspectToken)
	if err != nil {
		return intr, fmt.Errorf("introspecting token: %w", err)
	}

	h.cache.Set(cacheKey, intr, 0)

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
