package extauthz

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/extauthz/internal/handler"
	"github.com/openkcm/extauthz/internal/policies/cedarpolicy"
)

type jwtHeader struct {
	Typ string `json:"typ"`
	JKU string `json:"jku,omitempty"`
}

type jwtClaims struct {
	Subject string   `json:"sub"`
	Issuer  string   `json:"iss"`
	EMail   string   `json:"mail"`
	Groups  []string `json:"groups,omitempty"`
}

// checkJWTToken checks the request using the JWT bearer token.
func (srv *Server) checkJWTToken(ctx context.Context, bearerToken, method, host, path string) checkResult {
	// Parse the header for basic checks. Also extract the JKU/jwksURI to be able
	// to use it in permission checks. This is important because the issuer itself
	// may not be unique. With the JKU we can distinguish tokens from different
	// providers using the same issuer.
	parts := strings.Split(bearerToken, ".")
	if len(parts) != 3 {
		slogctx.Error(ctx, "Not a JWT token: could not split token")
		return checkResult{is: UNAUTHENTICATED, info: "Not a JWT token: could not split token"}
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		// Log the token header. Never ever log the signature!
		slogctx.Error(ctx, "Could not decode token header", "header", parts[0])
		return checkResult{is: UNAUTHENTICATED, info: fmt.Sprintf("Could not decode token header: %v", err)}
	}
	var header jwtHeader
	err = json.Unmarshal(headerBytes, &header)
	if err != nil {
		// Log the token header. Never ever log the signature!
		slogctx.Error(ctx, "Could not unmarshal token header", "header", parts[0])
		return checkResult{is: UNAUTHENTICATED, info: fmt.Sprintf("Could not unmarshal token header: %v", err)}
	}

	// parse and validate the token and extract the claims
	useCache := method == http.MethodGet // Allow using cache for token introspection for GET requests
	tenantID := srv.extractTenantID(path)
	var claims jwtClaims
	err = srv.oidcHandler.ParseAndValidate(ctx, bearerToken, tenantID, &claims, useCache)
	if err != nil {
		// Log the token header and payload. Never ever log the signature!
		slogctx.Error(ctx, "JWT validation failed", "error", err, "header", parts[0], "payload", parts[1])

		switch {
		case errors.Is(err, handler.ErrInvalidToken):
			return checkResult{is: UNAUTHENTICATED,
				info: "Invalid authorization header"}
		case errors.Is(err, handler.ErrNoProvider):
			return checkResult{is: DENIED,
				info: "No provider found"}
		}

		return checkResult{is: UNAUTHENTICATED,
			info: fmt.Sprintf("Error from JWT validation: %v", err)}
	}

	// prepare the result
	res := checkResult{
		is:      UNKNOWN,
		subject: claims.Subject,
		email:   claims.EMail,
		groups:  claims.Groups,
		authContext: map[string]string{
			"issuer": claims.Issuer,
		},
	}

	// check the policies
	slogctx.Debug(ctx, "Checking policies for JWT",
		"subject", claims.Subject,
		"issuer", claims.Issuer,
		"jwksURI", header.JKU,
		"method", method,
		"host", host,
		"path", path,
	)

	data := map[string]string{
		"route":   host + path, // TODO: remove when policies are updated to use host and path instead of route
		"host":    host,
		"path":    path,
		"type":    "jwt",
		"issuer":  claims.Issuer,
		"jwksURI": header.JKU,
	}

	allowed, reason, err := srv.policyEngine.Check(
		cedarpolicy.WithSubject(claims.Subject),
		cedarpolicy.WithAction(method),
		//nolint:staticcheck
		cedarpolicy.WithRoute(host+path), // TODO: remove when policies are updated to use host and path instead of route
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
