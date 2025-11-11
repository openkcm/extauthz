// Package oidc implements OIDC token handling in a multi-tenant environment.
// For this a Handler is created, which holds the Providers for validating tokens.
// You can either register providers in a static manner, or inject a client to
// query providers during runtime.
package oidc

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/patrickmn/go-cache"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/extauthz/internal/config"
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
	remoteProvider RemoteProvider

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

func WithRemoteProvider(remoteProvider RemoteProvider) HandlerOption {
	return func(handler *Handler) error {
		handler.remoteProvider = remoteProvider

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
