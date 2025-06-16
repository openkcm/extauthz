package extauthz

import (
	"context"
	"encoding/json"
	"log/slog"

	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/go-andiamo/splitter"
	"github.com/openkcm/common-sdk/pkg/auth"
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
)

type checkResult struct {
	is      checkResultCode
	info    string
	subject string
	email   string
	region  string
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
	}
}

// Ensure Server implements the AuthorizationServer interface
var _ envoy_auth.AuthorizationServer = &Server{}

// Check processes the JWT token and/or client certificate to authorize the request.
func (srv *Server) Check(ctx context.Context, req *envoy_auth.CheckRequest) (*envoy_auth.CheckResponse, error) {
	// check the header
	if req == nil ||
		req.Attributes == nil ||
		req.Attributes.Request == nil ||
		req.Attributes.Request.Http == nil ||
		req.Attributes.Request.Http.Headers == nil {
		slog.Debug("Check() called with nil request")
		return respondUnauthenticated("Invalid request"), nil
	}

	// log the header for debugging
	jsonBytes, err := json.MarshalIndent(req.Attributes.Request.Http, "", "  ")
	if err != nil {
		slog.Debug("Check() called with invalid request", "error", err)
		return respondUnauthenticated("Invalid request"), nil
	}
	slog.Debug("Check() called", "request", string(jsonBytes))

	// extract client certificate and authorization header
	certHeader, certHeaderFound := req.Attributes.Request.Http.Headers[HeaderForwardedClientCert]
	authHeader, authHeaderFound := req.Attributes.Request.Http.Headers[HeaderAuthorization]

	// return early if both are missing
	if !certHeaderFound && !authHeaderFound {
		return respondUnauthenticated("Missing client certificate and authorization header"), nil
	}

	// prepare the result and run the checks
	// each check may update the result if it is more restrictive
	result := checkResult{is: UNKNOWN}
	if certHeaderFound {
		// there can be multiple certificates in the XFCC header
		certHeaderParts, err := splitCertHeader(certHeader)
		if err != nil {
			return respondUnauthenticated("Invalid certificate header"), nil
		}
		for _, part := range certHeaderParts {
			result.merge(srv.checkClientCert(ctx, part,
				req.Attributes.Request.Http.Method,
				req.Attributes.Request.Http.Host,
				req.Attributes.Request.Http.Path))
		}
	}
	if authHeaderFound {
		result.merge(srv.checkAuthHeader(ctx, authHeader,
			req.Attributes.Request.Http.Method,
			req.Attributes.Request.Http.Host,
			req.Attributes.Request.Http.Path))
	}

	// process the result
	switch result.is {
	case ALLOWED:
		clientData := &auth.ClientData{
			SignatureAlgorithm: auth.SignatureAlgorithmRS256,
			Subject:            result.subject,
		}
		if srv.enrichHeaderWithType {
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
		if srv.enrichHeaderWithRegion && result.region != "" {
			clientData.Region = result.region
		}
		// get the public key
		keyID, publicKey, err := srv.signingKeyFunc()
		if err != nil {
			slog.Error("Failed to get public key", "error", err)
			return respondInternalServerError(), nil
		}
		// encode and sign the client data
		clientData.KeyID = keyID
		b64data, b64sig, err := clientData.Encode(publicKey)
		if err != nil {
			slog.Error("Failed to encode client data", "error", err)
			return respondInternalServerError(), nil
		}
		headers := []*envoy_core.HeaderValueOption{
			headerValueOption(auth.HeaderClientData, b64data),
			headerValueOption(auth.HeaderClientDataSignature, b64sig),
		}
		// remove other headers the backend shall not see
		headersToRemove := []string{HeaderForwardedClientCert}
		return respondAllowed(headers, headersToRemove), nil
	case UNKNOWN, UNAUTHENTICATED:
		return respondUnauthenticated(result.info), nil
	}
	return respondPermissionDenied(), nil
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
