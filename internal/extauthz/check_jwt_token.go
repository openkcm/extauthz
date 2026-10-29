package extauthz

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/extauthz/internal/clientdata"
	"github.com/openkcm/extauthz/internal/config"
	"github.com/openkcm/extauthz/internal/handler"
	"github.com/openkcm/extauthz/internal/policies/cedarpolicy"
)

type jwtHeader struct {
	Typ string `json:"typ"`
	JKU string `json:"jku,omitempty"`
}

type jwtUserAttributes struct {
	Groups []string `json:"groups,omitempty"`
}

type jwtClaims struct {
	Subject        string            `json:"sub"`
	Issuer         string            `json:"iss"`
	Audience       any               `json:"aud"` // string or []string depending on provider
	EMail          string            `json:"mail"`
	Email          string            `json:"email"`
	GivenName      string            `json:"given_name"`
	FamilyName     string            `json:"family_name"`
	Groups         []string          `json:"groups,omitempty"`
	UserAttributes jwtUserAttributes `json:"user_attributes"`
	AppTID         string            `json:"app_tid"`
	SapIDType      string            `json:"sap_id_type"`
}

// checkJWTToken dispatches to checkEnrichedJWTToken when the request path
// matches a configured prefix rule, otherwise falls through to checkStandardJWTToken.
func (srv *Server) checkJWTToken(ctx context.Context, bearerToken string, req requestInfo) checkResult {
	for _, rule := range srv.jwtPathPrefixRules {
		if strings.HasPrefix(req.path, rule.PathPrefix) {
			return srv.checkEnrichedJWTToken(ctx, bearerToken, req, rule)
		}
	}
	return srv.checkStandardJWTToken(ctx, bearerToken, req)
}

// checkEnrichedJWTToken validates the token and extracts claims according to
// the matched path-prefix rule. Required claims are enforced; missing or
// non-matching claims produce DENIED.
func (srv *Server) checkEnrichedJWTToken(ctx context.Context, bearerToken string, req requestInfo, rule config.JWTPathPrefixRule) checkResult {
	parts := strings.Split(bearerToken, ".")
	if len(parts) != 3 {
		slogctx.Error(ctx, "Not a JWT token: could not split token")
		return checkResult{is: UNAUTHENTICATED, info: "Not a JWT token: could not split token"}
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		slogctx.Error(ctx, "Could not decode token header", "header", parts[0])
		return checkResult{is: UNAUTHENTICATED, info: fmt.Sprintf("Could not decode token header: %v", err)}
	}
	var header jwtHeader
	if err = json.Unmarshal(headerBytes, &header); err != nil {
		slogctx.Error(ctx, "Could not unmarshal token header", "header", parts[0])
		return checkResult{is: UNAUTHENTICATED, info: fmt.Sprintf("Could not unmarshal token header: %v", err)}
	}

	useCache := req.method == http.MethodGet
	var rawClaims map[string]any
	err = srv.oidcHandler.ParseAndValidate(ctx, bearerToken, req.tenantID, &rawClaims, useCache)
	if err != nil {
		// Log the token header and payload. Never ever log the signature!
		slogctx.Error(ctx, "JWT validation failed", "error", err, "header", parts[0], "payload", parts[1])
		switch {
		case errors.Is(err, handler.ErrInvalidToken):
			return checkResult{is: UNAUTHENTICATED, info: "Invalid authorization header"}
		case errors.Is(err, handler.ErrNoProvider):
			return checkResult{is: DENIED, info: "No provider found"}
		}
		return checkResult{is: UNAUTHENTICATED, info: fmt.Sprintf("Error from JWT validation: %v", err)}
	}

	// Validate required claims.
	for _, rc := range rule.RequiredClaims {
		raw, exists := rawClaims[rc.Field]
		if !exists {
			return checkResult{is: DENIED, info: fmt.Sprintf("required claim %q is missing", rc.Field)}
		}
		switch rc.MatchType {
		case config.ClaimMatchTypeEquals:
			s, ok := raw.(string)
			if !ok || s != rc.Value {
				return checkResult{is: DENIED, info: fmt.Sprintf("required claim %q does not equal %q", rc.Field, rc.Value)}
			}
		case config.ClaimMatchTypeContains:
			arr, ok := raw.([]any)
			if !ok {
				return checkResult{is: DENIED, info: fmt.Sprintf("required claim %q is not an array", rc.Field)}
			}
			found := false
			for _, v := range arr {
				if s, ok := v.(string); ok && s == rc.Value {
					found = true
					break
				}
			}
			if !found {
				return checkResult{is: DENIED, info: fmt.Sprintf("required claim %q does not contain %q", rc.Field, rc.Value)}
			}
		default:
			return checkResult{is: DENIED, info: fmt.Sprintf("required claim %q has unknown match type %q", rc.Field, rc.MatchType)}
		}
	}

	// Extract standard fields.
	subject, _ := rawClaims["sub"].(string)
	issuer, _ := rawClaims["iss"].(string)

	// Extract email with mail fallback.
	email, _ := rawClaims["email"].(string)
	if email == "" {
		email, _ = rawClaims["mail"].(string)
	}

	// Extract names and groups.
	givenName, _ := rawClaims["given_name"].(string)
	familyName, _ := rawClaims["family_name"].(string)
	var groups []string
	if arr, ok := rawClaims["groups"].([]any); ok {
		for _, v := range arr {
			if s, ok := v.(string); ok {
				groups = append(groups, s)
			}
		}
	}
	if len(groups) == 0 {
		if ua, ok := rawClaims["user_attributes"].(map[string]any); ok {
			if arr, ok := ua["groups"].([]any); ok {
				for _, v := range arr {
					if s, ok := v.(string); ok {
						groups = append(groups, s)
					}
				}
			}
		}
	}

	// Build auth context.
	authCtx := map[string]string{contextKeyIssuer: issuer}
	if clientID := firstAudienceString(rawClaims["aud"]); clientID != "" {
		authCtx["client_id"] = clientID
	}
	for _, field := range rule.AdditionalAuthContextFields {
		if field == contextKeyIssuer || field == "client_id" {
			continue
		}
		if s, ok := rawClaims[field].(string); ok && s != "" {
			authCtx[field] = s
		}
	}

	// Derive client type from mapping.
	var clientTypeOverride *clientdata.ClientType
	if rule.ClientTypeField != "" {
		if fieldVal, ok := rawClaims[rule.ClientTypeField].(string); ok {
			if mapped, ok := rule.ClientTypeMapping[fieldVal]; ok {
				var ct clientdata.ClientType
				switch mapped {
				case "TechnicalUser":
					ct = clientdata.TechnicalUser
				case "System":
					ct = clientdata.System
				case "User":
					ct = clientdata.User
				}
				if ct != "" {
					clientTypeOverride = &ct
				}
			}
		}
	}

	res := checkResult{
		is:                 UNKNOWN,
		subject:            subject,
		email:              email,
		givenname:          givenName,
		familyname:         familyName,
		groups:             groups,
		authContext:        authCtx,
		clientTypeOverride: clientTypeOverride,
	}

	slogctx.Debug(ctx, "Checking policies for enriched JWT",
		"issuer", issuer,
		"jwksURI", header.JKU,
		"method", req.method,
		"host", req.host,
		"path", req.path,
	)

	data := map[string]string{
		contextKeyHost:   req.host,
		contextKeyPath:   req.path,
		contextKeyType:   authTypeJWT,
		contextKeyIssuer: issuer,
		"jwksURI":        header.JKU,
	}

	allowed, reason, err := srv.policyEngine.Check(
		cedarpolicy.WithSubject(subject),
		cedarpolicy.WithAction(req.method),
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

// checkStandardJWTToken checks the request using the JWT bearer token with the standard claim set.
func (srv *Server) checkStandardJWTToken(ctx context.Context, bearerToken string, req requestInfo) checkResult {
	// Parse the header for basic checks. Also extract the JKU/jwksURI to be able
	// to use it in permission checks. This is important because the issuer itself
	// may not be unique. With the JKU we can distinguish tokens from different
	// providers using the same issuer.
	parts := strings.Split(bearerToken, ".")
	if len(parts) != 3 {
		slogctx.Error(ctx, "Not a JWT token: could not split token")
		return checkResult{is: UNAUTHENTICATED, info: "Not a JWT token: could not split token"}
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		// Log the token header. Never ever log the signature!
		slogctx.Error(ctx, "Could not decode token header", "header", parts[0])
		return checkResult{is: UNAUTHENTICATED, info: fmt.Sprintf("Could not decode token header: %v", err)}
	}
	var header jwtHeader
	err = json.Unmarshal(headerBytes, &header)
	if err != nil {
		// Log the token header. Never ever log the signature!
		slogctx.Error(ctx, "Could not unmarshal token header", "header", parts[0])
		return checkResult{is: UNAUTHENTICATED, info: fmt.Sprintf("Could not unmarshal token header: %v", err)}
	}

	// parse and validate the token and extract the claims
	useCache := req.method == http.MethodGet // Allow using cache for token introspection for GET requests
	var claims jwtClaims
	err = srv.oidcHandler.ParseAndValidate(ctx, bearerToken, req.tenantID, &claims, useCache)
	if err != nil {
		// Log the token header and payload. Never ever log the signature!
		slogctx.Error(ctx, "JWT validation failed", "error", err, "header", parts[0], "payload", parts[1])

		switch {
		case errors.Is(err, handler.ErrInvalidToken):
			return checkResult{is: UNAUTHENTICATED,
				info: "Invalid authorization header"}
		case errors.Is(err, handler.ErrNoProvider):
			return checkResult{is: DENIED,
				info: "No provider found"}
		}

		return checkResult{is: UNAUTHENTICATED,
			info: fmt.Sprintf("Error from JWT validation: %v", err)}
	}

	// prepare the result
	email := claims.Email
	if email == "" {
		email = claims.EMail
	}

	groups := claims.Groups
	if len(groups) == 0 {
		groups = claims.UserAttributes.Groups
	}

	authCtx := map[string]string{
		contextKeyIssuer: claims.Issuer,
	}
	if claims.AppTID != "" {
		authCtx["app_tid"] = claims.AppTID
	}
	if clientID := firstAudienceString(claims.Audience); clientID != "" {
		authCtx["client_id"] = clientID
	}

	res := checkResult{
		is:         UNKNOWN,
		subject:    claims.Subject,
		email:      email,
		givenname:  claims.GivenName,
		familyname: claims.FamilyName,
		groups:     groups,
		authContext: authCtx,
	}

	// check the policies
	slogctx.Debug(ctx, "Checking policies for JWT",
		"issuer", claims.Issuer,
		"jwksURI", header.JKU,
		"method", req.method,
		"host", req.host,
		"path", req.path,
	)

	data := map[string]string{
		contextKeyHost:   req.host,
		contextKeyPath:   req.path,
		contextKeyType:   authTypeJWT,
		contextKeyIssuer: claims.Issuer,
		"jwksURI":        header.JKU,
	}

	allowed, reason, err := srv.policyEngine.Check(
		cedarpolicy.WithSubject(claims.Subject),
		cedarpolicy.WithAction(req.method),
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

// firstAudienceString extracts the first audience value from an aud claim that
// may be either a string or a []interface{} (JSON unmarshals both forms into any).
func firstAudienceString(aud any) string {
	switch v := aud.(type) {
	case string:
		return v
	case []interface{}:
		if len(v) > 0 {
			if s, ok := v[0].(string); ok {
				return s
			}
		}
	}
	return ""
}
