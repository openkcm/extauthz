package extauthz

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-andiamo/splitter"
	"github.com/openkcm/common-sdk/pkg/auth"

	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/extauthz/internal/flags"
)

const (
	HeaderForwardedClientCert = "x-forwarded-client-cert"
	HeaderAuthorization       = "authorization"
	HeaderCookie              = "cookie"
	SessionCookieName         = "__Host-Http-SESSION"
)

// Ensure Server implements the AuthorizationServer interface
var _ envoy_auth.AuthorizationServer = &Server{}

// Check authorizes the request based on either client certificate, bearer token or session cookie.
func (srv *Server) Check(ctx context.Context, req *envoy_auth.CheckRequest) (*envoy_auth.CheckResponse, error) {
	// check the header
	if req == nil ||
		req.GetAttributes() == nil ||
		req.GetAttributes().GetRequest() == nil ||
		req.GetAttributes().GetRequest().GetHttp() == nil ||
		req.GetAttributes().GetRequest().GetHttp().GetHeaders() == nil {
		slogctx.Debug(ctx, "Check() called with nil request")
		return respondUnauthenticated("Invalid request"), nil
	}

	// log the header for debugging
	httpreq := req.GetAttributes().GetRequest().GetHttp()
	headers := httpreq.GetHeaders()
	method := httpreq.GetMethod()
	host := httpreq.GetHost()
	path := httpreq.GetPath()
	slogctx.Debug(ctx, "Check() called",
		"id", httpreq.GetId(),
		"protocol", httpreq.GetProtocol(),
		"method", method,
		"sheme", httpreq.GetScheme(),
		"host", host,
		"path", path,
	)

	// Authenticate in the following order:
	// 1. Client certificates
	// 2. Bearer token in the authorization header
	// 3. Session cookie
	// All results are merged, the most restrictive result wins.
	result := checkResult{is: UNKNOWN}

	// Verify if DisableClientCertificateComputation flag was explicitly set in the configuration with value `true`, then the
	// Client Certificates handling should be disabled
	// TODO: Remove this hacking code when session support is added and tested
	skipClientCertificates := false
	if srv.featureGates.IsFeatureEnabled(flags.DisableClientCertificateComputation) {
		slogctx.Error(ctx, "Check() processing of client certificate has been disabled through feature gates")
		result.is = ALWAYS_ALLOW
		skipClientCertificates = true
	}

	// Verify if DisableJWTTokenComputation flag was explicitly set in the configuration with value `true`, then the
	// bearer token handling should be disabled
	// TODO: Remove this hacking code when session support is added and tested
	skipBearerToken := false
	if srv.featureGates.IsFeatureEnabled(flags.DisableJWTTokenComputation) {
		slogctx.Error(ctx, "Check() processing of bearer token has been disabled through feature gates")
		result.is = ALWAYS_ALLOW
		skipBearerToken = true
	}

	// TODO: Remove this hacking code when session support is added and tested
	if !skipClientCertificates {
		// 1. Client certificates (if any)
		if clientCerts, found := extractClientCertificates(headers); found {
			slogctx.Debug(ctx, "Checking client certificate")
			for nr, part := range clientCerts {
				slogctx.Debug(ctx, "Checking client certificate", "part", nr)
				result.merge(srv.checkClientCert(ctx, part, method, host, path))
				result.withXFCCHeader = true
			}
		}
	}

	// TODO: Remove this hacking code when session support is added and tested
	if !skipBearerToken {
		// 2. Bearer token in the authorization header (if any)
		if bearerToken, found := extractBearerToken(headers); found {
			slogctx.Debug(ctx, "Checking bearer token from authorization header")
			result.merge(srv.checkJWTToken(ctx, bearerToken, method, host, path))
		}
	}

	// 3. Session cookie (if any and only if session cache is configured)
	if srv.sessionCache != nil {
		if sessionCookie, tenantID, found := srv.extractSessionCookieAndTenantID(headers, path); found {
			slogctx.Debug(ctx, "Checking session cookie")
			result.merge(srv.checkSession(ctx, sessionCookie, tenantID, method, host, path))
		}
	}

	// Log the result for debugging
	ctx = slogctx.WithGroup(ctx, "result")
	slogctx.Debug(ctx, "Check() result",
		"is", result.is,
		"info", result.info,
		"subject", result.subject)

	// Prepare the response
	switch result.is {
	case ALLOWED:
		headersToAdd := []*envoy_core.HeaderValueOption{}
		headersToRemove := []string{HeaderForwardedClientCert}

		if srv.clientDataSigner == nil || srv.clientDataSigner.IsDisabled() {
			return respondAllowed(headersToAdd, headersToRemove), nil
		}

		b64data, b64sig, err := srv.clientDataSigner.Sign(
			result.toClientDataOptions()...,
		)
		if err != nil {
			slogctx.Error(ctx, "Failed to encode client data", "error", err)
			return respondInternalServerError(), nil
		}

		headersToAdd = []*envoy_core.HeaderValueOption{
			headerValueOption(auth.HeaderClientData, b64data),
			headerValueOption(auth.HeaderClientDataSignature, b64sig),
		}

		return respondAllowed(headersToAdd, headersToRemove), nil
	case ALWAYS_ALLOW:
		return respondAllowed([]*envoy_core.HeaderValueOption{}, []string{}), nil
	case UNKNOWN, UNAUTHENTICATED:
		return respondUnauthenticated(result.info), nil
	}

	return respondPermissionDenied(), nil
}

func extractClientCertificates(headers map[string]string) ([]string, bool) {
	certHeader, found := headers[HeaderForwardedClientCert]
	if !found {
		return nil, false
	}
	// there can be multiple certificates in the XFCC header
	certHeaderParts, err := splitCertHeader(certHeader)
	if err != nil {
		return nil, false
	}

	return certHeaderParts, true
}

func extractBearerToken(headers map[string]string) (string, bool) {
	authHeader, found := headers[HeaderAuthorization]
	if !found {
		return "", false
	}

	prefix, bearerToken, found := strings.Cut(authHeader, " ")
	if !found || prefix != "Bearer" {
		return "", false
	}

	return bearerToken, true
}

func (srv *Server) extractSessionCookieAndTenantID(headers map[string]string, path string) (*http.Cookie, string, bool) {
	// extract tenant ID from the path
	var tenantID string
	switch {
	case strings.HasPrefix(path, srv.cmkPathPrefix): // /cmk/v1/{tenantID}/...
		parts := strings.Split(path, "/")
		if len(parts) < 4 {
			return nil, "", false
		}
		tenantID = parts[3]
	default:
		return nil, "", false
	}

	// extract the session cookie
	cookieHeader, found := headers[HeaderCookie]
	if !found {
		return nil, "", false
	}
	cookies, err := http.ParseCookie(cookieHeader)
	if err != nil {
		return nil, "", false
	}
	for _, cookie := range cookies {
		if cookie.Name == SessionCookieName {
			return cookie, tenantID, true
		}
	}

	return nil, "", false
}

// splitCertHeader splits the XFCC header on , in case there are multiple certificates.
// https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert
func splitCertHeader(certHeader string) ([]string, error) {
	// split on , preserving quoted values
	spl, err := splitter.NewSplitter(',', splitter.DoubleQuotes)
	if err != nil {
		return nil, err
	}

	fields, err := spl.Split(certHeader)
	if err != nil {
		return nil, err
	}

	return fields, nil
}
