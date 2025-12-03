package extauthz

import (
	"context"
	"fmt"
	"net/http"

	"github.com/openkcm/common-sdk/pkg/csrf"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/extauthz/internal/policies/cedarpolicy"
)

// checkSession checks the request using the session Cookie.
func (srv *Server) checkSession(ctx context.Context, sessionCookie *http.Cookie, tenantID, fingerprint, method, host, path, csrfToken string) checkResult {
	if sessionCookie == nil {
		slogctx.Debug(ctx, "Session cookie is nil")
		return checkResult{is: UNKNOWN}
	}

	// On GetSession the session manager will:
	// - check if the session exists for this session ID and tenant ID
	// - compare the fingerprints
	// - validate the session (expiry, token revocation, ...)
	// If the session is valid, it will return the session details.
	session, err := srv.sessionManager.GetSession(ctx, sessionCookie.Value, tenantID, fingerprint)
	if err != nil {
		slogctx.Debug(ctx, "Failed to get session from session manager", "error", err)
		return checkResult{is: UNAUTHENTICATED,
			info: fmt.Sprintf("failed to get session from session manager: %v", err),
		}
	}

	if !session.Valid {
		slogctx.Debug(ctx, "Session is not valid")
		return checkResult{is: UNAUTHENTICATED,
			info: "session is not valid",
		}
	}

	if !csrf.Validate(csrfToken, sessionCookie.Value, srv.csrfSecret) {
		slogctx.Debug(ctx, "CSRF token is not valid")
		return checkResult{
			is:   UNAUTHENTICATED,
			info: "CSRF token is not valid",
		}
	}

	// prepare the result
	res := checkResult{
		is:          UNKNOWN,
		subject:     session.Subject,
		givenname:   session.GivenName,
		familyname:  session.FamilyName,
		email:       session.Email,
		groups:      session.Groups,
		authContext: session.AuthContext,
	}

	// check the policies
	slogctx.Debug(ctx, "Checking policies for session",
		"subject", session.Subject,
		"issuer", session.Issuer,
		"method", method,
		"host", host,
		"path", path,
	)

	data := map[string]string{
		"route":  host + path,
		"type":   "jwt",
		"issuer": session.Issuer,
	}

	allowed, reason, err := srv.policyEngine.Check(
		cedarpolicy.WithSubject(session.Subject),
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
