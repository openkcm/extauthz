package extauthz

import (
	"context"
	"errors"
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

	allowIntrospectCache := method == "GET" // Allow using cache for token introspection for GET requests
	if err := srv.jwtHandler.ParseAndValidate(ctx, tokenString, &claims, allowIntrospectCache); err != nil {
		switch {
		case errors.Is(err, jwthandler.ErrInvalidToken):
			return checkResult{is: UNAUTHENTICATED,
				info: "Invalid authorization header"}
		case errors.Is(err, jwthandler.ErrNoProvider):
			return checkResult{is: DENIED,
				info: "No provider found"}
		}
		return checkResult{is: UNAUTHENTICATED,
			info: err.Error()}
	}

	// check the policies
	allowed, reason, err := srv.policyEngine.Check(claims.Subject, method, host+path,
		map[string]string{
			"type":   "jwt",
			"issuer": claims.Issuer,
		})
	if err != nil {
		return checkResult{is: UNAUTHENTICATED,
			info: err.Error()}
	}
	if !allowed {
		return checkResult{is: DENIED,
			info: reason}
	}

	return checkResult{
		is:      ALLOWED,
		subject: claims.Subject,
		email:   claims.EMail,
	}
}
