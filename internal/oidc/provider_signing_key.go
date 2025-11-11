package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-jose/go-jose/v4"
	"github.com/patrickmn/go-cache"

	slogctx "github.com/veqryn/slog-context"
)

// lookupSigningKey returns the key for the given key.
func (p *Provider) lookupSigningKey(ctx context.Context, keyID string) (*jose.JSONWebKey, error) {
	// check the cache first
	key, found := getSigningKey(p.cacheSignKeys, keyID)
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
		storeSigningKey(p.cacheSignKeys, keyID, checkedKey)
		return checkedKey, nil
	}

	// return an error if the key was not found
	return nil, fmt.Errorf("could not find key for key ID %s", keyID)
}

// getSigningKey retrieves a signing key from the provided in-memory cache.
//
// It looks up a key by its key ID (`keyID`) in the given cache instance (`keycache`).
// If the cache is nil, or the key does not exist or has an unexpected type,
// the function returns (nil, false).
//
// Returns:
//   - *jose.JSONWebKey: the cached signing key if found and valid.
//   - bool: true if a valid key was found and type-asserted successfully; false otherwise.
func getSigningKey(keycache *cache.Cache, keyID string) (*jose.JSONWebKey, bool) {
	if keycache == nil {
		return nil, false
	}

	keyInterface, found := keycache.Get(keyID)
	if found {
		key, ok := keyInterface.(*jose.JSONWebKey)
		return key, ok
	}

	return nil, false
}

// storeSigningKey saves a signing key into the provided cache using its key ID.
//
// The function safely returns if the cache is nil. It stores the key with
// the default expiration configured in the cache (using cache.DefaultExpiration),
// meaning the entry will respect the global TTL settings.
//
// See: https://pkg.go.dev/github.com/patrickmn/go-cache#Cache.Set
func storeSigningKey(keycache *cache.Cache, keyID string, key *jose.JSONWebKey) {
	if keycache == nil {
		return
	}

	keycache.Set(keyID, key, cache.DefaultExpiration)
}

// lookupValidSigningKey searches for a valid signing key within a given JSON Web Key Set (JWKS).
//
// It iterates through all keys in the provided `keySet`, and for each key,
// runs `validateSigningKey` to ensure the key matches the requested `keyID`
// and is designated for signing (i.e., key.Use == "sig").
//
// Returns:
//   - *jose.JSONWebKey: the matching signing key if found.
//   - bool: true if a valid signing key is found, false otherwise.
func lookupValidSigningKey(keyID string, keySet *jose.JSONWebKeySet) (*jose.JSONWebKey, bool) {
	for _, k := range keySet.Keys {
		if checkedKey := validateSigningKey(keyID, &k); checkedKey != nil {
			return checkedKey, true
		}
	}
	return nil, false
}

// validateSigningKey verifies whether a given key is a valid signing key for the provided key ID.
//
// The function ensures:
//   - The key's "use" field equals "sig" (signing purpose).
//   - The key's ID matches the given keyID.
//
// Returns the key itself if valid, otherwise returns nil.
func validateSigningKey(keyID string, key *jose.JSONWebKey) *jose.JSONWebKey {
	if key.Use != "sig" {
		return nil
	}

	if key.KeyID != keyID {
		return nil
	}

	return key
}
