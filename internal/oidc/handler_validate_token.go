package oidc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	slogctx "github.com/veqryn/slog-context"
)

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

	// let the h lookup the identity provider for the issuer host
	provider, err := h.lookupProviderByIssuer(ctx, issuer)
	if err != nil {
		slogctx.Error(ctx, "Failed to get provider for issuer", "error", err, "issuer", issuer)
		return errors.Join(ErrNoProvider, err)
	}

	// read the key ID from the token headers
	// Not sure why there are multiple headers, take the first one with key ID
	keyID := extractHeaderKeyID(token.Headers)
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

func extractHeaderKeyID(headers []jose.Header) string {
	for _, header := range headers {
		if header.KeyID != "" {
			return header.KeyID
		}
	}
	return ""
}
