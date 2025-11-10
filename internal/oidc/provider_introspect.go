package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

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
