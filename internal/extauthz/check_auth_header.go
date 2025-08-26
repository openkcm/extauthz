package extauthz

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/extauthz/internal/jwthandler"
	"github.com/openkcm/extauthz/internal/policies/cedarpolicy"
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
		Subject string   `json:"sub"`
		Issuer  string   `json:"iss"`
		EMail   string   `json:"mail"`
		Groups  []string `json:"groups,omitempty"`
	}{}

	allowIntrospectCache := method == http.MethodGet // Allow using cache for token introspection for GET requests

	err := srv.jwtHandler.ParseAndValidate(ctx, tokenString, &claims, allowIntrospectCache)
	if err != nil {
		slogctx.Debug(ctx, "JWT validation failed", "error", err)

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

	// prepare the result
	res := checkResult{
		is:      UNKNOWN,
		subject: claims.Subject,
		email:   claims.EMail,
		groups:  claims.Groups,
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
