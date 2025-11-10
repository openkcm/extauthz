package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/extauthz/internal/utils"
)

type wellKnownOpenIDConfiguration struct {
	Issuer                string `json:"issuer"`
	JWKSURI               string `json:"jwks_uri"`
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"` // optional
}

func (p *Provider) extractDataFromWellKnownConfiguration(ctx context.Context) error {
	if utils.CheckAllPopulated(p.jwksURL, p.introspectURL) {
		return nil
	}

	wkoc := wellKnownOpenIDConfiguration{}
	wkocURI := p.issuerURL.JoinPath(".well-known/openid-configuration")

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, wkocURI.String(), nil)
	if err != nil {
		return fmt.Errorf("could not build request to get well known OpenID configuration: %w", err)
	}

	response, err := p.client.Do(request)
	if err != nil {
		return fmt.Errorf("could not get well known OpenID configuration: %w", err)
	}

	defer func() {
		err := response.Body.Close()
		if err != nil {
			slogctx.Error(ctx, "could not close response body", "error", err)
		}
	}()

	// decode the well known OpenID configuration
	err = json.NewDecoder(response.Body).Decode(&wkoc)
	if err != nil {
		return fmt.Errorf("could not decode well known OpenID configuration: %w", err)
	}

	p.jwksURL, err = parseEndpoint(wkoc.JWKSURI)
	if err != nil {
		return fmt.Errorf("could not parse JWKS URI: %w", err)
	}

	p.introspectURL, err = parseEndpoint(wkoc.IntrospectionEndpoint)
	if err != nil {
		return fmt.Errorf("could not parse introspection endpoint: %w", err)
	}

	return nil
}
