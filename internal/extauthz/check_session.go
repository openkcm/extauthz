package extauthz

import (
	"context"
	"fmt"
	"net/http"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/extauthz/internal/policies/cedarpolicy"
)

// checkSession checks the request using the session Cookie.
func (srv *Server) checkSession(ctx context.Context, sessionCookie *http.Cookie, tenantID, method, host, path string) checkResult {
	if sessionCookie == nil {
		slogctx.Debug(ctx, "Session cookie is nil")
		return checkResult{is: UNKNOWN}
	}

	session, err := srv.sessionCache.LoadSession(ctx, sessionCookie.Value)
	if err != nil {
		slogctx.Debug(ctx, "Failed to load session from session store", "error", err)
		return checkResult{is: UNAUTHENTICATED,
			info: fmt.Sprintf("failed to load session from session store: %v", err),
		}
	}

	if session.TenantID != tenantID {
		slogctx.Debug(ctx, "Session tenant ID does not match", "sessionTenantID", session.TenantID, "expectedTenantID", tenantID)
		return checkResult{is: UNAUTHENTICATED,
			info: fmt.Sprintf("failed to load session from session store: %v", err),
		}
	}

	// Allow using cache for token introspection for GET requests
	allowIntrospectCache := method == http.MethodGet

	// Verify if token is not revoked
	intr, err := srv.oidcHandler.Introspect(ctx, session.Issuer, session.AccessToken, session.AccessToken, allowIntrospectCache)
	if err != nil {
		slogctx.Debug(ctx, "Failed to introspect token", "error", err)
		return checkResult{is: UNAUTHENTICATED,
			info: fmt.Sprintf("failed to introspect token: %v", err),
		}
	}
	if !intr.Active {
		return checkResult{is: UNAUTHENTICATED,
			info: "token is not active",
		}
	}

	// TODO: need to store this in the session
	subject := "me"
	email := ""
	groups := []string{}

	// prepare the result
	res := checkResult{
		is:      UNKNOWN,
		subject: subject,
		email:   email,
		groups:  groups,
		issuer:  session.Issuer,
	}

	// check the policies
	slogctx.Debug(ctx, "Checking policies for session",
		"subject", subject,
		"issuer", session.Issuer,
		"method", method,
		"host", host,
		"path", path)

	data := map[string]string{
		"route":  host + path,
		"type":   "jwt",
		"issuer": session.Issuer,
	}

	allowed, reason, err := srv.policyEngine.Check(
		cedarpolicy.WithSubject(subject),
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
