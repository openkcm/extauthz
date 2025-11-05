package extauthz

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/extauthz/internal/oidc"
	"github.com/openkcm/extauthz/internal/policies/cedarpolicy"
)

// checkJWTToken checks the request using the JWT bearer token.
func (srv *Server) checkJWTToken(ctx context.Context, bearerToken, method, host, path string) checkResult {
	// parse and validate the token and extract the claims
	claims := struct {
		Subject string   `json:"sub"`
		Issuer  string   `json:"iss"`
		EMail   string   `json:"mail"`
		Groups  []string `json:"groups,omitempty"`
	}{}

	useCache := method == http.MethodGet // Allow using cache for token introspection for GET requests

	err := srv.oidcHandler.ParseAndValidate(ctx, bearerToken, &claims, useCache)
	if err != nil {
		slogctx.Debug(ctx, "JWT validation failed", "error", err)

		switch {
		case errors.Is(err, oidc.ErrInvalidToken):
			return checkResult{is: UNAUTHENTICATED,
				info: "Invalid authorization header"}
		case errors.Is(err, oidc.ErrNoProvider):
			return checkResult{is: DENIED,
				info: "No provider found"}
		}

		return checkResult{is: UNAUTHENTICATED,
			info: fmt.Sprintf("Error from JWT validation: %v", err)}
	}

	rawClaims, err := jwtPayload(bearerToken)
	if err != nil {
		slogctx.Error(ctx, "Extracting JSON payload from JWT failed", "error", err)
		return checkResult{is: UNAUTHENTICATED,
			info: "Invalid authorization header"}
	}

	// prepare the result
	res := checkResult{
		is:        UNKNOWN,
		subject:   claims.Subject,
		email:     claims.EMail,
		groups:    claims.Groups,
		issuer:    claims.Issuer,
		rawClaims: rawClaims,
	}

	// check the policies
	slogctx.Debug(ctx, "Checking policies for JWT",
		"subject", claims.Subject,
		"issuer", claims.Issuer,
		"method", method,
		"host", host,
		"path", path)

	data := map[string]string{
		"route":  host + path,
		"type":   "jwt",
		"issuer": claims.Issuer,
	}

	allowed, reason, err := srv.policyEngine.Check(
		cedarpolicy.WithSubject(claims.Subject),
		cedarpolicy.WithAction(method),
		cedarpolicy.WithRoute(host+path),
		cedarpolicy.WithContextData(data),
	)
	if err != nil {
		res.is = UNAUTHENTICATED
		res.info = fmt.Sprintf("Error from policy engine: %v", err)
		return res
	}

	if !allowed {
		res.is = DENIED
		res.info = fmt.Sprintf("Reason from policy engine: %v", reason)
		return res
	}

	res.is = ALLOWED
	return res
}

// jwtPayload returns the raw JSON payload from a JWT token
func jwtPayload(tokenString string) (string, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid JWT token")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("could not decode JWT payload")
	}
	return string(payloadBytes), nil
}
