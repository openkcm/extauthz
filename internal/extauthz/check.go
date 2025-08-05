package extauthz

import (
	"context"

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
)

type userType string

const (
	User          userType = "user"
	TechnicalUser userType = "technical-user"
	System        userType = "system"
)

type checkResultCode uint

const (
	UNKNOWN checkResultCode = iota
	ALLOWED
	DENIED
	UNAUTHENTICATED

	ALWAYS_ALLOW = 100
)

type checkResult struct {
	is      checkResultCode
	info    string
	subject string
	email   string
	region  string
	groups  []string
}

// merge updates the result if the other result is more restrictive
func (cr *checkResult) merge(other checkResult) {
	// UNKNOWN < ALLOWED < DENIED < UNAUTHENTICATED
	if other.is > cr.is {
		cr.is = other.is
		cr.info = other.info
		cr.subject = other.subject
		cr.email = other.email
		cr.region = other.region
		cr.groups = other.groups
	}
}

// Ensure Server implements the AuthorizationServer interface
var _ envoy_auth.AuthorizationServer = &Server{}

// Check processes the JWT token and/or client certificate to authorize the request.
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
	slogctx.Debug(ctx, "Check() called",
		"id", httpreq.GetId(),
		"protocol", httpreq.GetProtocol(),
		"method", httpreq.GetMethod(),
		"sheme", httpreq.GetScheme(),
		"host", httpreq.GetHost(),
		"path", httpreq.GetPath(),
		"headers", httpreq.GetHeaders(),
	)

	// extract client certificate and authorization header
	certHeader, certHeaderFound := req.GetAttributes().GetRequest().GetHttp().GetHeaders()[HeaderForwardedClientCert]
	authHeader, authHeaderFound := req.GetAttributes().GetRequest().GetHttp().GetHeaders()[HeaderAuthorization]

	result := checkResult{is: UNKNOWN}

	// Verify if DisableJWTTokenComputation flag was explicitly set in the configuration with value `true`, then the
	// JWT tokens handling should be disabled
	// TODO: Remove this hacking code in September
	if srv.featureGates.IsFeatureEnabled(flags.DisableJWTTokenComputation) {
		slogctx.Error(ctx, "Check() processing of jwt token has been disabled through feature gates")

		result.is = ALWAYS_ALLOW
		authHeaderFound = false
	}

	// Verify if DisableClientCertificateComputation flag was explicitly set in the configuration with value `true`, then the
	// Client Certificates handling should be disabled
	// TODO: Remove this hacking code in September
	if srv.featureGates.IsFeatureEnabled(flags.DisableClientCertificateComputation) {
		slogctx.Error(ctx, "Check() processing of client certificate has been disabled through feature gates")

		result.is = ALWAYS_ALLOW
		certHeaderFound = false
	}

	if !certHeaderFound && !authHeaderFound {
		result.info = "Missing client certificate or authorization header"
		slogctx.Error(ctx, "Check() "+result.info)
		// TODO: Enable this line once the above code was removed in September
		//return respondUnauthenticated(result.info), nil
	}

	// prepare the result and run the checks
	// each check may update the result if it is more restrictive
	if certHeaderFound {
		// there can be multiple certificates in the XFCC header
		certHeaderParts, err := splitCertHeader(certHeader)
		if err != nil {
			return respondUnauthenticated("Invalid certificate header"), nil
		}

		for _, part := range certHeaderParts {
			slogctx.Debug(ctx, "Check() processing certificate part", "part", part)
			result.merge(srv.checkClientCert(ctx, part,
				req.GetAttributes().GetRequest().GetHttp().GetMethod(),
				req.GetAttributes().GetRequest().GetHttp().GetHost(),
				req.GetAttributes().GetRequest().GetHttp().GetPath()))
		}
	}

	if authHeaderFound {
		slogctx.Debug(ctx, "Check() processing authorization header")
		result.merge(srv.checkAuthHeader(ctx, authHeader,
			req.GetAttributes().GetRequest().GetHttp().GetMethod(),
			req.GetAttributes().GetRequest().GetHttp().GetHost(),
			req.GetAttributes().GetRequest().GetHttp().GetPath()))
	}

	// process the result
	slogctx.Debug(ctx, "Check() result", "result", result.is, "info", result.info, "subject", result.subject)

	switch result.is {
	case ALLOWED:
		clientData := &auth.ClientData{
			SignatureAlgorithm: auth.SignatureAlgorithmRS256,
			Subject:            result.subject,
		}

		enrichHeaderWithType := srv.featureGates.IsFeatureEnabled(flags.EnrichHeaderWithClientType)
		if enrichHeaderWithType {
			clientType := User

			switch {
			case certHeaderFound && result.email != "":
				clientType = TechnicalUser
			case certHeaderFound && result.email == "":
				clientType = System
			}

			clientData.Type = string(clientType)
			if result.email != "" {
				clientData.Email = result.email
			}
		}

		enrichHeaderWithRegion := srv.featureGates.IsFeatureEnabled(flags.EnrichHeaderWithClientRegion)
		if enrichHeaderWithRegion && result.region != "" {
			clientData.Region = result.region
		}

		if len(result.groups) > 0 {
			clientData.Groups = result.groups
		}
		// get the public key
		keyID, publicKey, err := srv.signingKeyFunc()
		if err != nil {
			slogctx.Error(ctx, "Failed to get public key", "error", err)
			return respondInternalServerError(), nil
		}
		// encode and sign the client data
		clientData.KeyID = keyID

		b64data, b64sig, err := clientData.Encode(publicKey)
		if err != nil {
			slogctx.Error(ctx, "Failed to encode client data", "error", err)
			return respondInternalServerError(), nil
		}

		headers := []*envoy_core.HeaderValueOption{
			headerValueOption(auth.HeaderClientData, b64data),
			headerValueOption(auth.HeaderClientDataSignature, b64sig),
		}
		// remove other headers the backend shall not see
		headersToRemove := []string{HeaderForwardedClientCert}

		return respondAllowed(headers, headersToRemove), nil
	case ALWAYS_ALLOW:
		return respondAllowed([]*envoy_core.HeaderValueOption{}, []string{}), nil
	case UNKNOWN, UNAUTHENTICATED:
		return respondUnauthenticated(result.info), nil
	}

	return respondPermissionDenied(), nil
}

// splitCertHeader splits the XFCC header on , in case there are multiple certificates.
// https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert
func splitCertHeader(certHeader string) ([]string, error) {
	// split on ; preserving quoted values
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
