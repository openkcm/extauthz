package extauthz

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-andiamo/splitter"
	"github.com/openkcm/common-sdk/pkg/auth"
	"github.com/openkcm/common-sdk/pkg/fingerprint"

	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/extauthz/internal/flags"
)

const (
	HeaderForwardedClientCert = "x-forwarded-client-cert"
	HeaderAuthorization       = "authorization"
	HeaderCookie              = "cookie"
	HeaderCSRFToken           = "X-CSRF-Token"
	SessionCookieName         = "__Host-Http-SESSION"
	LogPrefixCheck            = "Check(): "
	LogPrefixClientCert       = "Client Certs: "
	LogPrefixBearerToken      = "Bearer Token: "
	LogPrefixSessionCookie    = "Session cookie: "
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
		slogctx.Debug(ctx, LogPrefixCheck+"called with nil request")
		return respondUnauthenticated("Invalid request"), nil
	}

	// log the header for debugging
	httpreq := req.GetAttributes().GetRequest().GetHttp()
	headers := httpreq.GetHeaders()
	method := httpreq.GetMethod()
	host := httpreq.GetHost()
	path := httpreq.GetPath()
	ctx = slogctx.With(ctx,
		"id", httpreq.GetId(),
		"protocol", httpreq.GetProtocol(),
		"method", method,
		"sheme", httpreq.GetScheme(),
		"host", host,
		"path", path,
	)
	slogctx.Debug(ctx, LogPrefixCheck+"called")

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
		slogctx.Error(ctx, LogPrefixCheck+"processing of client certificate has been disabled through feature gates")
		result.is = ALWAYS_ALLOWED
		skipClientCertificates = true
	}

	// Verify if DisableJWTTokenComputation flag was explicitly set in the configuration with value `true`, then the
	// bearer token handling should be disabled
	// TODO: Remove this hacking code when session support is added and tested
	skipBearerToken := false
	if srv.featureGates.IsFeatureEnabled(flags.DisableJWTTokenComputation) {
		slogctx.Error(ctx, LogPrefixCheck+"processing of bearer token has been disabled through feature gates")
		result.is = ALWAYS_ALLOWED
		skipBearerToken = true
	}

	// TODO: Remove this hacking code when session support is added and tested
	if !skipClientCertificates {
		// 1. Client certificates (if any)
		slogctx.Debug(ctx, LogPrefixClientCert+"checking for presence")
		if clientCerts, found := extractClientCertificates(ctx, headers); !found {
			slogctx.Debug(ctx, LogPrefixClientCert+"not found")
		} else {
			slogctx.Debug(ctx, LogPrefixClientCert+"found", "count", len(clientCerts))
			for nr, part := range clientCerts {
				slogctx.Debug(ctx, fmt.Sprintf(LogPrefixClientCert+"checking number %d", nr))
				r := srv.checkClientCert(ctx, part, method, host, path)
				slogctx.Debug(ctx, LogPrefixClientCert+"access "+r.is.String(), "part", nr)
				result.merge(r)
				result.withXFCCHeader = true
			}
		}
	}

	// TODO: Remove this hacking code when session support is added and tested
	if !skipBearerToken {
		// 2. Bearer token in the authorization header (if any)
		slogctx.Debug(ctx, LogPrefixBearerToken+"checking for presence")
		if bearerToken, found := extractBearerToken(ctx, headers); !found {
			slogctx.Debug(ctx, LogPrefixBearerToken+"not found")
		} else {
			slogctx.Debug(ctx, LogPrefixBearerToken+"found ... checking")
			r := srv.checkJWTToken(ctx, bearerToken, method, host, path)
			slogctx.Debug(ctx, LogPrefixBearerToken+"access "+r.is.String())
			result.merge(r)
		}
	}

	// 3. Session cookie (if any and only if session manager is configured)
	if srv.sessionManager != nil {
		slogctx.Debug(ctx, LogPrefixSessionCookie+"checking for presence")
		if sessionCookie, tenantID, fingerPrint, found := srv.extractSessionDetails(ctx, httpreq, path); !found {
			slogctx.Debug(ctx, LogPrefixSessionCookie+"not found")
		} else {
			slogctx.Debug(ctx, LogPrefixSessionCookie+"found ... checking")
			csrfToken := headers[HeaderCSRFToken]
			r := srv.checkSession(ctx, sessionCookie, tenantID, fingerPrint, method, host, path, csrfToken)
			slogctx.Debug(ctx, LogPrefixSessionCookie+"access "+r.is.String())
			result.merge(r)
		}
	}

	// Log the result for debugging
	ctx = slogctx.WithGroup(ctx, "result")
	slogctx.Debug(ctx, LogPrefixCheck+"overall result: access "+result.is.String(),
		"info", result.info,
		"subject", result.subject,
	)

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
			slogctx.Error(ctx, LogPrefixCheck+"failed to encode client data", "error", err)
			return respondInternalServerError(), nil
		}

		slogctx.Debug(ctx, LogPrefixCheck+"client data",
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
		slogctx.Debug(ctx, LogPrefixClientCert+"no XFCC header found", "headers", mapKeys(headers))
		return nil, false
	}
	// there can be multiple certificates in the XFCC header
	certHeaderParts, err := splitCertHeader(certHeader)
	if err != nil {
		slogctx.Debug(ctx, LogPrefixClientCert+"failed to split XFCC header", "error", err)
		return nil, false
	}

	return certHeaderParts, true
}

func extractBearerToken(ctx context.Context, headers map[string]string) (string, bool) {
	authHeader, found := headers[HeaderAuthorization]
	if !found {
		slogctx.Debug(ctx, LogPrefixBearerToken+"no authorization header found", "headers", mapKeys(headers))
		return "", false
	}

	prefix, bearerToken, found := strings.Cut(authHeader, " ")
	if !found || prefix != "Bearer" {
		slogctx.Debug(ctx, LogPrefixBearerToken+"authorization header does not contain Bearer token")
		return "", false
	}

	return bearerToken, true
}

func (srv *Server) extractSessionDetails(ctx context.Context, httpreq *envoy_auth.AttributeContext_HttpRequest, path string) (*http.Cookie, string, string, bool) {
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
		slogctx.Debug(ctx, LogPrefixSessionCookie+"failed to extract tenant ID from path", "sessionPathPrefixes", srv.sessionPathPrefixes)
		return nil, "", "", false
	}

	// Determine the fingerprint for this request.
	fp, err := fingerprint.NewBuilder().FromEnvoyHTTPRequest(httpreq)
	if err != nil {
		slogctx.Debug(ctx, LogPrefixSessionCookie+"failed to compute fingerprint from request", "error", err)
		return nil, "", "", false
	}

	// extract the session cookie
	cookieHeader, found := headers[HeaderCookie]
	if !found {
		slogctx.Debug(ctx, LogPrefixSessionCookie+"no cookie header found", "headers", mapKeys(headers))
		return nil, "", "", false
	}
	cookies, err := http.ParseCookie(cookieHeader)
	if err != nil {
		slogctx.Debug(ctx, LogPrefixSessionCookie+"failed to parse cookie header", "error", err)
		return nil, "", "", false
	}
	for _, cookie := range cookies {
		if cookie.Name == SessionCookieName {
			slogctx.Debug(ctx, LogPrefixSessionCookie+"found session cookie", "name", cookie.Name)
			return cookie, tenantID, fp, true
		}
	}

	slogctx.Debug(ctx, LogPrefixSessionCookie+"session cookie not found", "sessionCookieName", SessionCookieName)
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
