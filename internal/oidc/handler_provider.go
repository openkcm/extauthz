package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/patrickmn/go-cache"
	slogctx "github.com/veqryn/slog-context"
)

// lookupProviderByIssuer returns the provider for the given issuer. It either looks up the
// provider in the internal cache or queries the provider client.
func (h *Handler) lookupProviderByIssuer(ctx context.Context, issuerURLString string) (*Provider, error) {
	issuerURL, err := url.Parse(issuerURLString)
	if err != nil {
		slogctx.Error(ctx, "Failed to parse issuer URL", "error", err, "issuer", issuerURLString)
		return nil, errors.Join(ErrInvalidToken, err)
	}

	if issuerURL.Scheme != "https" {
		slogctx.Error(ctx, "Invalid issuer scheme", "scheme", issuerURL.Scheme)
		return nil, errors.Join(ErrInvalidToken, fmt.Errorf("invalid issuer scheme %s", issuerURL.Scheme))
	}

	issuer := issuerURL.Host

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
	if h.remoteProvider != nil {
		p, err := h.remoteProvider.Get(ctx, issuer)
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
