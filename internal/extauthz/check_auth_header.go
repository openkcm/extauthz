package extauthz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/openkcm/extauthz/internal/jwthandler"
)

// checkAuthHeader checks the request using the authorization header, which should contain a JWT token.
func (srv *Server) checkAuthHeader(ctx context.Context, authHeader, method, host, path string) checkResult {
	// extract the token from the authorization header
	prefix, tokenString, ok := strings.Cut(authHeader, " ")
	if !ok || prefix != "Bearer" {
		return checkResult{is: UNAUTHENTICATED,
			info: "Invalid authorization header"}
	}

	// parse and validate the token and extract the claims
	claims := struct {
		Subject string `json:"sub"`
		Issuer  string `json:"iss"`
		EMail   string `json:"mail"`
	}{}

	allowIntrospectCache := method == http.MethodGet // Allow using cache for token introspection for GET requests
	if err := srv.jwtHandler.ParseAndValidate(ctx, tokenString, &claims, allowIntrospectCache); err != nil {
		slog.Debug("JWT validation failed", "error", err)
		switch {
		case errors.Is(err, jwthandler.ErrInvalidToken):
			return checkResult{is: UNAUTHENTICATED,
				info: "Invalid authorization header"}
		case errors.Is(err, jwthandler.ErrNoProvider):
			return checkResult{is: DENIED,
				info: "No provider found"}
		}
		return checkResult{is: UNAUTHENTICATED,
			info: fmt.Sprintf("Error from JWT validation: %v", err)}
	}

	// check the policies
	slog.Debug("Checking policies for JWT",
		"subject", claims.Subject,
		"issuer", claims.Issuer,
		"method", method,
		"host", host,
		"path", path)
	allowed, reason, err := srv.policyEngine.Check(claims.Subject, method, host+path,
		map[string]string{
			"type":   "jwt",
			"issuer": claims.Issuer,
		})
	if err != nil {
		return checkResult{is: UNAUTHENTICATED,
			info: fmt.Sprintf("Error from policy engine: %v", err)}
	}
	if !allowed {
		return checkResult{is: DENIED,
			info: fmt.Sprintf("Reason from policy engine: %v", reason)}
	}

	return checkResult{
		is:      ALLOWED,
		subject: claims.Subject,
		email:   claims.EMail,
	}
}
