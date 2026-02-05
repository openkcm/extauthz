package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	slogctx "github.com/veqryn/slog-context"
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

	// Error response fields e.g. bad credentials
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func (provider *Provider) Introspect(ctx context.Context, introspectToken string) (Introspection, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.IntrospectURL.String(), nil)
	if err != nil {
		return Introspection{}, fmt.Errorf("creating new http request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	q := req.URL.Query()
	q.Set("token", introspectToken)
	req.URL.RawQuery = q.Encode()

	resp, err := provider.httpClient.Do(req)
	if err != nil {
		return Introspection{}, fmt.Errorf("executing http request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Introspection{}, fmt.Errorf("reading introspection response body: %w", err)
	}

	var intr Introspection
	err = json.Unmarshal(body, &intr)
	if err != nil {
		slogctx.Error(ctx, "Failed to unmarshal introspection response", "body", string(body), "error", err)
		return Introspection{}, fmt.Errorf("decoding introspection response: %w", err)
	}

	return intr, nil
}

func makeDefaultIntrospectURL(base *url.URL) *url.URL {
	return base.JoinPath("oauth2", "introspect")
}
