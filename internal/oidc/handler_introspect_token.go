package oidc

import (
	"context"
	"fmt"

	"github.com/openkcm/extauthz/internal/flags"
)

// IntrospectToken an access or refresh token with the given issuer.
func (h *Handler) IntrospectToken(ctx context.Context, issuer, bearerToken, introspectToken string, useCache bool) (Introspection, error) {
	// let the h lookup the identity provider for the issuer host
	provider, err := h.lookupProviderByIssuer(ctx, issuer)
	if err != nil {
		return Introspection{}, err
	}

	// Verify if token is not revoked
	return h.introspect(ctx, provider, bearerToken, introspectToken, useCache)
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
