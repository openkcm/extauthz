package extauthz

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/openkcm/common-sdk/pkg/auth"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	envoycore "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoyauth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	slogctx "github.com/veqryn/slog-context"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
)

const (
	HeaderForwardedClientCert = "x-forwarded-client-cert"
	HeaderAuthorization       = "authorization"
	HeaderCookie              = "cookie"
	HeaderCSRFToken           = "x-csrf-token"
	SessionCookiePrefix       = "__Host-Http-SESSION-"
	LogPrefixCheck            = "Check(): "
	LogPrefixClientCert       = "Client Certs: "
	LogPrefixBearerToken      = "Bearer Token: "
	LogPrefixSessionCookie    = "Session cookie: "
)

// Ensure Server implements the AuthorizationServer interface
var _ envoyauth.AuthorizationServer = &Server{}

// Span and attribute names for the per-Check application span.
const (
	spanNameCheck     = "ext_authz.check"
	spanAttrDecision  = "ext_authz.decision"
	spanAttrAuthType  = "ext_authz.auth_type"
	HeaderTraceparent = "traceparent"
	HeaderTracestate  = "tracestate"
	HeaderBaggage     = "baggage"
)

// Check authorizes the request based on either client certificate, bearer token or session cookie.
func (srv *Server) Check(ctx context.Context, req *envoyauth.CheckRequest) (*envoyauth.CheckResponse, error) {
	// check the header
	if req == nil ||
		req.GetAttributes() == nil ||
		req.GetAttributes().GetRequest() == nil ||
		req.GetAttributes().GetRequest().GetHttp() == nil ||
		req.GetAttributes().GetRequest().GetHttp().GetHeaders() == nil {
		slogctx.Debug(ctx, LogPrefixCheck+"called with nil request")
		return respondUnauthenticated("Invalid request")
	}

	// log the header for debugging
	httpreq := req.GetAttributes().GetRequest().GetHttp()
	headers := httpreq.GetHeaders()
	method := httpreq.GetMethod()
	host := httpreq.GetHost()
	path := httpreq.GetPath()

	// Extract W3C trace context from the inbound HTTP headers carried by the
	// CheckRequest. Envoy delivers header keys lower-cased, which is what the
	// OTel TextMapPropagator expects. When traceparent is missing or malformed
	// the propagator returns ctx unchanged (per OTel spec).
	ctx = otel.GetTextMapPropagator().Extract(ctx, propagation.MapCarrier(headers))

	ctx = slogctx.With(ctx,
		"id", httpreq.GetId(),
		"protocol", httpreq.GetProtocol(),
		"method", method,
		"scheme", httpreq.GetScheme(),
		"host", host,
		"path", path,
	)

	// Start the application span as a child of the extracted context. Span
	// kind is server because ExtAuthz is handling an inbound gRPC call.
	ctx, span := srv.tracer.Start(ctx, spanNameCheck,
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(
			semconv.HTTPRequestMethodKey.String(method),
			semconv.URLPath(path),
			semconv.ServerAddress(host),
		),
	)
	defer span.End()

	slogctx.Debug(ctx, LogPrefixCheck+"called")

	// Authenticate in the following order:
	// 1. Client certificates
	// 2. Bearer token in the authorization header
	// 3. Session cookie
	// All results are merged, the most restrictive result wins.
	result := checkResult{is: UNKNOWN}

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
			r.kind = authKindX509
			result.merge(r)
			result.withXFCCHeader = true
		}
	}

	// 2. Bearer token in the authorization header (if any)
	slogctx.Debug(ctx, LogPrefixBearerToken+"checking for presence")
	if bearerToken, found := extractBearerToken(ctx, headers); !found {
		slogctx.Debug(ctx, LogPrefixBearerToken+"not found")
	} else {
		slogctx.Debug(ctx, LogPrefixBearerToken+"found ... checking")
		r := srv.checkJWTToken(ctx, bearerToken, method, host, path)
		slogctx.Debug(ctx, LogPrefixBearerToken+"access "+r.is.String())
		r.kind = authKindJWT
		result.merge(r)
	}

	// 3. Session cookie (if any and only if session manager is configured)
	if srv.sessionManager != nil {
		slogctx.Debug(ctx, LogPrefixSessionCookie+"checking for presence")
		if sessionCookie, tenantID, found := srv.extractSessionDetails(ctx, httpreq, path); !found {
			slogctx.Debug(ctx, LogPrefixSessionCookie+"not found")
		} else {
			slogctx.Debug(ctx, LogPrefixSessionCookie+"found ... checking")
			csrfToken := headers[HeaderCSRFToken]
			r := srv.checkSession(ctx, sessionCookie, tenantID, method, host, path, csrfToken)
			slogctx.Debug(ctx, LogPrefixSessionCookie+"access "+r.is.String())
			r.kind = authKindSession
			result.merge(r)
		}
	}

	// Log the result for debugging
	ctx = slogctx.WithGroup(ctx, "result")
	slogctx.Debug(ctx, LogPrefixCheck+"overall result: access "+result.is.String(),
		"info", result.info,
		"subject", result.subject,
	)

	// Decorate the span with the post-merge decision and credential channel.
	span.SetAttributes(
		attribute.String(spanAttrDecision, result.is.String()),
		attribute.String(spanAttrAuthType, result.authType()),
	)
	if result.is == ALLOWED {
		span.SetStatus(codes.Ok, "")
	} else {
		span.SetStatus(codes.Error, result.info)
	}

	// Prepare the response
	switch result.is {
	case ALLOWED:
		headersToAdd := []*envoycore.HeaderValueOption{}
		headersToRemove := []string{HeaderForwardedClientCert}

		if srv.clientDataSigner == nil {
			return respondAllowed(headersToAdd, headersToRemove), nil
		}

		b64data, b64sig, err := srv.clientDataSigner.Sign(
			result.toClientDataOptions()...,
		)
		if err != nil {
			slogctx.Error(ctx, LogPrefixCheck+"failed to encode client data", "error", err)
			return respondInternalServerError()
		}

		slogctx.Debug(ctx, LogPrefixCheck+"client data", auth.HeaderClientData, b64data)
		headersToAdd = []*envoycore.HeaderValueOption{
			headerValueOption(auth.HeaderClientData, b64data),
			headerValueOption(auth.HeaderClientDataSignature, b64sig),
		}

		return respondAllowed(headersToAdd, headersToRemove), nil
	case UNKNOWN, UNAUTHENTICATED:
		return respondUnauthenticated(result.info)
	case TENANT_BLOCKED:
		return respondTenantBlocked()
	}

	return respondPermissionDenied()
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

func (srv *Server) extractTenantID(path string) string {
	// extract tenant ID from the path
	for _, prefix := range srv.sessionPathPrefixes {
		remainder, found := strings.CutPrefix(path, prefix)
		if !found {
			continue
		}
		parts := strings.SplitN(remainder, "/", 2)
		return parts[0]
	}

	return ""
}

func (srv *Server) extractSessionDetails(ctx context.Context, httpreq *envoyauth.AttributeContext_HttpRequest, path string) (*http.Cookie, string, bool) {
	headers := httpreq.GetHeaders()
	tenantID := srv.extractTenantID(path)
	if tenantID == "" {
		slogctx.Debug(ctx, LogPrefixSessionCookie+"failed to extract tenant ID from path", "sessionPathPrefixes", srv.sessionPathPrefixes)
		return nil, "", false
	}

	// extract the tenant specific session cookie
	cookieHeader, found := headers[HeaderCookie]
	if !found {
		slogctx.Debug(ctx, LogPrefixSessionCookie+"no cookie header found", "headers", mapKeys(headers))
		return nil, "", false
	}
	cookies, err := http.ParseCookie(cookieHeader)
	if err != nil {
		slogctx.Debug(ctx, LogPrefixSessionCookie+"failed to parse cookie header", "error", err)
		return nil, "", false
	}
	sessionCookieName := SessionCookiePrefix + tenantID
	var sessionCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == sessionCookieName {
			slogctx.Debug(ctx, LogPrefixSessionCookie+"found tenant specific session cookie", "name", sessionCookieName)
			sessionCookie = cookie
			break
		}
	}

	// return if no session cookie found
	if sessionCookie == nil {
		slogctx.Debug(ctx, LogPrefixSessionCookie+"tenant specific session cookie not found", "name", sessionCookieName)
		return nil, "", false
	}

	return sessionCookie, tenantID, true
}

// splitCertHeader splits the XFCC header on , in case there are multiple certificates.
// https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert
func splitCertHeader(certHeader string) ([]string, error) {
	// Handle empty string case
	if certHeader == "" {
		return []string{}, nil
	}

	// Manual parsing to preserve quotes and handle XFCC format correctly
	var fields []string
	var current strings.Builder
	inQuote := false
	escaped := false

	for i := range len(certHeader) {
		ch := certHeader[i]

		if inQuote && escaped {
			// Previous character was a backslash, so write this character as-is
			current.WriteByte(ch)
			escaped = false
			continue
		}

		switch ch {
		case '\\':
			if inQuote {
				// Mark that the next character is escaped (only inside quotes per XFCC spec)
				escaped = true
			}
			current.WriteByte(ch)
		case '"':
			// Toggle quote state
			inQuote = !inQuote
			current.WriteByte(ch)
		case ',':
			if inQuote {
				// Inside quotes, comma is part of the value
				current.WriteByte(ch)
			} else {
				// Outside quotes, comma is a separator
				fields = append(fields, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(ch)
		}
	}

	// Add the last field
	fields = append(fields, current.String())

	// Check for unclosed quotes
	if inQuote {
		return nil, errors.New("unclosed quote in header")
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
