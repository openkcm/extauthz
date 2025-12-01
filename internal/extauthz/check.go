package extauthz

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-andiamo/splitter"
	"github.com/openkcm/common-sdk/pkg/auth"
	"github.com/openkcm/session-manager/pkg/fingerprint"

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
		result.is = ALWAYS_ALLOWED
		skipClientCertificates = true
	}

	// Verify if DisableJWTTokenComputation flag was explicitly set in the configuration with value `true`, then the
	// bearer token handling should be disabled
	// TODO: Remove this hacking code when session support is added and tested
	skipBearerToken := false
	if srv.featureGates.IsFeatureEnabled(flags.DisableJWTTokenComputation) {
		slogctx.Error(ctx, "Check() processing of bearer token has been disabled through feature gates")
		result.is = ALWAYS_ALLOWED
		skipBearerToken = true
	}

	// TODO: Remove this hacking code when session support is added and tested
	if !skipClientCertificates {
		// 1. Client certificates (if any)
		slogctx.Debug(ctx, "Checking if client certificates are present")
		if clientCerts, found := extractClientCertificates(ctx, headers); found {
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
		slogctx.Debug(ctx, "Checking if bearer token is present in authorization header")
		if bearerToken, found := extractBearerToken(ctx, headers); found {
			slogctx.Debug(ctx, "Checking bearer token from authorization header")
			result.merge(srv.checkJWTToken(ctx, bearerToken, method, host, path))
		}
	}

	// 3. Session cookie (if any and only if session manager is configured)
	if srv.sessionManager != nil {
		slogctx.Debug(ctx, "Checking if session cookie is present")
		if sessionCookie, tenantID, fingerPrint, found := srv.extractSessionDetails(ctx, httpreq, path); found {
			slogctx.Debug(ctx, "Checking session cookie")
			result.merge(srv.checkSession(ctx, sessionCookie, tenantID, fingerPrint, method, host, path))
		}
	}

	// Log the result for debugging
	ctx = slogctx.WithGroup(ctx, "result")
	slogctx.Debug(ctx, "Check() result: Access "+result.is.String(),
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

		slogctx.Debug(ctx, "Client data",
			auth.HeaderClientData, b64data,
			auth.HeaderClientDataSignature, b64sig,
		)
		headersToAdd = []*envoy_core.HeaderValueOption{
			headerValueOption(auth.HeaderClientData, b64data),
			headerValueOption(auth.HeaderClientDataSignature, b64sig),
		}

		return respondAllowed(headersToAdd, headersToRemove), nil
	case ALWAYS_ALLOWED:
		return respondAllowed([]*envoy_core.HeaderValueOption{}, []string{}), nil
	case UNKNOWN, UNAUTHENTICATED:
		return respondUnauthenticated(result.info), nil
	}

	return respondPermissionDenied(), nil
}

func extractClientCertificates(ctx context.Context, headers map[string]string) ([]string, bool) {
	certHeader, found := headers[HeaderForwardedClientCert]
	if !found {
		slogctx.Debug(ctx, "No XFCC header found", "headers", mapKeys(headers))
		return nil, false
	}
	// there can be multiple certificates in the XFCC header
	certHeaderParts, err := splitCertHeader(certHeader)
	if err != nil {
		slogctx.Debug(ctx, "Failed to split XFCC header", "error", err)
		return nil, false
	}

	return certHeaderParts, true
}

func extractBearerToken(ctx context.Context, headers map[string]string) (string, bool) {
	authHeader, found := headers[HeaderAuthorization]
	if !found {
		slogctx.Debug(ctx, "No authorization header found", "headers", mapKeys(headers))
		return "", false
	}

	prefix, bearerToken, found := strings.Cut(authHeader, " ")
	if !found || prefix != "Bearer" {
		slogctx.Debug(ctx, "Authorization header does not contain Bearer token")
		return "", false
	}

	return bearerToken, true
}

func (srv *Server) extractSessionDetails(ctx context.Context, httpreq *envoy_auth.AttributeContext_HttpRequest, path string) (*http.Cookie, string, string, bool) {
	ctx = slogctx.With(ctx, "path", path)
	headers := httpreq.GetHeaders()

	// extract tenant ID from the path
	var tenantID string
	for _, prefix := range srv.sessionPathPrefixes {
		remainder, found := strings.CutPrefix(path, prefix)
		if !found {
			continue
		}
		parts := strings.SplitN(remainder, "/", 2)
		tenantID = parts[0]
	}
	if tenantID == "" {
		slogctx.Debug(ctx, "Failed to extract tenant ID from path", "sessionPathPrefixes", srv.sessionPathPrefixes)
		return nil, "", "", false
	}

	// Determine the fingerprint for this request.
	fp, err := fingerprint.FromEnvoyHTTPRequest(httpreq)
	if err != nil {
		slogctx.Debug(ctx, "Failed to compute fingerprint from request", "error", err)
		return nil, "", "", false
	}

	// extract the session cookie
	cookieHeader, found := headers[HeaderCookie]
	if !found {
		slogctx.Debug(ctx, "No cookie header found", "headers", mapKeys(headers))
		return nil, "", "", false
	}
	cookies, err := http.ParseCookie(cookieHeader)
	if err != nil {
		slogctx.Debug(ctx, "Failed to parse cookie header", "error", err)
		return nil, "", "", false
	}
	for _, cookie := range cookies {
		if cookie.Name == SessionCookieName {
			slogctx.Debug(ctx, "Found session cookie", "name", cookie.Name)
			return cookie, tenantID, fp, true
		}
	}

	slogctx.Debug(ctx, "Session cookie not found", "sessionCookieName", SessionCookieName)
	return nil, "", "", false
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

// Helper function to get map keys for debugging
func mapKeys[K comparable, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
