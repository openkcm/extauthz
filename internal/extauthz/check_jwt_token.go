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

type parsedJWTHeader struct {
	header    jwtHeader
	parts     []string
	errResult checkResult
	ok        bool
}

type jwtClaims struct {
	Subject    string   `json:"sub"`
	Issuer     string   `json:"iss"`
	Audience   any      `json:"aud"` // string or []string depending on provider
	ClientID   string   `json:"client_id"`
	Mail       string   `json:"mail"`
	Email      string   `json:"email"`
	GivenName  string   `json:"given_name"`
	FamilyName string   `json:"family_name"`
	Groups     []string `json:"groups,omitempty"`
}

// parseJWTHeader splits a bearer token into its three parts, decodes and
// unmarshals the header segment. Check ok before using header/parts.
func parseJWTHeader(ctx context.Context, bearerToken string) parsedJWTHeader {
	parts := strings.Split(bearerToken, ".")
	if len(parts) != 3 {
		slogctx.Error(ctx, "Not a JWT token: could not split token")
		return parsedJWTHeader{errResult: checkResult{is: UNAUTHENTICATED, info: "Not a JWT token: could not split token"}}
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		slogctx.Error(ctx, "Could not decode token header", "header", parts[0])
		return parsedJWTHeader{errResult: checkResult{is: UNAUTHENTICATED, info: fmt.Sprintf("Could not decode token header: %v", err)}}
	}
	var header jwtHeader
	err = json.Unmarshal(headerBytes, &header)
	if err != nil {
		slogctx.Error(ctx, "Could not unmarshal token header", "header", parts[0])
		return parsedJWTHeader{errResult: checkResult{is: UNAUTHENTICATED, info: fmt.Sprintf("Could not unmarshal token header: %v", err)}}
	}
	return parsedJWTHeader{header: header, parts: parts, ok: true}
}

// jwtValidationError maps a ParseAndValidate error to a checkResult.
func jwtValidationError(ctx context.Context, err error, parsed parsedJWTHeader) checkResult {
	// Log the token header and payload. Never ever log the signature!
	slogctx.Error(ctx, "JWT validation failed", "error", err, "header", parsed.parts[0], "payload", parsed.parts[1])
	switch {
	case errors.Is(err, handler.ErrInvalidToken):
		return checkResult{is: UNAUTHENTICATED, info: "Invalid authorization header"}
	case errors.Is(err, handler.ErrNoProvider):
		return checkResult{is: DENIED, info: "No provider found"}
	}
	return checkResult{is: UNAUTHENTICATED, info: fmt.Sprintf("Error from JWT validation: %v", err)}
}

// checkJWTToken dispatches to checkEnrichedJWTToken when the request path
// matches a configured prefix rule, otherwise falls through to checkStandardJWTToken.
func (srv *Server) checkJWTToken(ctx context.Context, bearerToken string, req requestInfo) checkResult {
	for _, rule := range srv.jwtPathPrefixRules {
		// rule.PathPrefix always has a trailing slash (guaranteed by WithJWTPathPrefixRules).
		// Match both the exact path without trailing slash and any path under the prefix.
		if strings.HasPrefix(req.path, rule.PathPrefix) || req.path == strings.TrimSuffix(rule.PathPrefix, "/") {
			return srv.checkEnrichedJWTToken(ctx, bearerToken, req, rule)
		}
	}
	return srv.checkStandardJWTToken(ctx, bearerToken, req)
}

// checkEnrichedJWTToken validates the token and extracts claims according to
// the matched path-prefix rule. Required claims are enforced; missing or
// non-matching claims produce DENIED.
func (srv *Server) checkEnrichedJWTToken(ctx context.Context, bearerToken string, req requestInfo, rule config.JWTPathPrefixRule) checkResult {
	parsed := parseJWTHeader(ctx, bearerToken)
	if !parsed.ok {
		return parsed.errResult
	}

	useCache := req.method == http.MethodGet
	var rawClaims map[string]any
	err := srv.oidcHandler.ParseAndValidate(ctx, bearerToken, req.tenantID, &rawClaims, useCache)
	if err != nil {
		return jwtValidationError(ctx, err, parsed)
	}

	if denyResult, deny := validateRequiredClaims(rawClaims, rule.RequiredClaims); deny {
		return denyResult
	}

	subject, ok := rawClaims["sub"].(string)
	if !ok || subject == "" {
		return checkResult{is: DENIED, info: "required claim \"sub\" is missing or empty"}
	}
	issuer, _ := rawClaims["iss"].(string)

	email, _ := rawClaims["email"].(string)
	if email == "" {
		email, _ = rawClaims["mail"].(string)
	}

	givenName, _ := rawClaims["given_name"].(string)
	familyName, _ := rawClaims["family_name"].(string)

	authCtx := buildAuthContext(issuer, rawClaims, rule.AdditionalAuthContextFields)

	res := checkResult{
		is:                 UNKNOWN,
		subject:            subject,
		email:              email,
		givenname:          givenName,
		familyname:         familyName,
		groups:             extractGroups(rawClaims),
		authContext:        authCtx,
		clientTypeOverride: deriveClientTypeOverride(rawClaims, rule),
	}

	slogctx.Debug(ctx, "Checking policies for enriched JWT",
		"issuer", issuer,
		"jwksURI", parsed.header.JKU,
		"method", req.method,
		"host", req.host,
		"path", req.path,
	)

	data := map[string]string{
		contextKeyHost:   req.host,
		contextKeyPath:   req.path,
		contextKeyType:   authTypeJWT,
		contextKeyIssuer: issuer,
		"jwksURI":        parsed.header.JKU,
	}

	allowed, reason, err := srv.policyEngine.Check(
		cedarpolicy.WithSubject(subject),
		cedarpolicy.WithAction(req.method),
		cedarpolicy.WithContextData(data),
	)
	if err != nil {
		res.is = DENIED
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

// validateRequiredClaims checks each RequiredClaim against rawClaims.
// Returns (denyResult, true) on the first failure, (zero, false) if all pass.
func validateRequiredClaims(rawClaims map[string]any, rules []config.RequiredClaim) (checkResult, bool) {
	for _, rc := range rules {
		raw, exists := rawClaims[rc.Field]
		if !exists {
			return checkResult{is: DENIED, info: fmt.Sprintf("required claim %q is missing", rc.Field)}, true
		}
		switch rc.MatchType {
		case config.ClaimMatchTypeEquals:
			s, ok := raw.(string)
			if !ok || s != rc.Value {
				return checkResult{is: DENIED, info: fmt.Sprintf("required claim %q does not equal %q", rc.Field, rc.Value)}, true
			}
		case config.ClaimMatchTypeContains:
			if deny, result := checkClaimContains(rc, raw); deny {
				return result, true
			}
		default:
			return checkResult{is: DENIED, info: fmt.Sprintf("required claim %q has unknown match type %q", rc.Field, rc.MatchType)}, true
		}
	}
	return checkResult{}, false
}

func checkClaimContains(rc config.RequiredClaim, raw any) (bool, checkResult) {
	arr, ok := raw.([]any)
	if !ok {
		return true, checkResult{is: DENIED, info: fmt.Sprintf("required claim %q is not an array", rc.Field)}
	}
	for _, v := range arr {
		if s, ok := v.(string); ok && s == rc.Value {
			return false, checkResult{}
		}
	}
	return true, checkResult{is: DENIED, info: fmt.Sprintf("required claim %q does not contain %q", rc.Field, rc.Value)}
}

// extractGroups returns the groups from the rawClaims "groups" array claim.
func extractGroups(rawClaims map[string]any) []string {
	if arr, ok := rawClaims["groups"].([]any); ok {
		groups := make([]string, 0, len(arr))
		for _, v := range arr {
			if s, ok := v.(string); ok {
				groups = append(groups, s)
			}
		}
		if len(groups) > 0 {
			return groups
		}
	}
	return nil
}

// buildAuthContext constructs the auth context map from standard and additional fields.
func buildAuthContext(issuer string, rawClaims map[string]any, additionalFields map[string]string) map[string]string {
	authCtx := map[string]string{contextKeyIssuer: issuer}
	if clientID, ok := rawClaims["client_id"].(string); ok && clientID != "" {
		authCtx["client_id"] = clientID
	}
	for claimName, ctxKey := range additionalFields {
		if ctxKey == contextKeyIssuer || ctxKey == "client_id" {
			continue
		}
		if s, ok := rawClaims[claimName].(string); ok && s != "" {
			authCtx[ctxKey] = s
		}
	}
	return authCtx
}

// deriveClientTypeOverride maps the ClientTypeField claim value to a clientdata.ClientType.
// Returns nil when the field is absent or the value is not in the mapping.
func deriveClientTypeOverride(rawClaims map[string]any, rule config.JWTPathPrefixRule) *clientdata.ClientType {
	if rule.ClientTypeField == "" {
		return nil
	}
	fieldVal, ok := rawClaims[rule.ClientTypeField].(string)
	if !ok {
		return nil
	}
	mapped, ok := rule.ClientTypeMapping[fieldVal]
	if !ok {
		return nil
	}
	ct := clientdata.ClientType(mapped)
	return &ct
}

// checkStandardJWTToken checks the request using the JWT bearer token with the standard claim set.
func (srv *Server) checkStandardJWTToken(ctx context.Context, bearerToken string, req requestInfo) checkResult {
	// Parse the header for basic checks. Also extract the JKU/jwksURI to be able
	// to use it in permission checks. This is important because the issuer itself
	// may not be unique. With the JKU we can distinguish tokens from different
	// providers using the same issuer.
	parsed := parseJWTHeader(ctx, bearerToken)
	if !parsed.ok {
		return parsed.errResult
	}

	// parse and validate the token and extract the claims
	useCache := req.method == http.MethodGet // Allow using cache for token introspection for GET requests
	var claims jwtClaims
	err := srv.oidcHandler.ParseAndValidate(ctx, bearerToken, req.tenantID, &claims, useCache)
	if err != nil {
		return jwtValidationError(ctx, err, parsed)
	}

	// prepare the result
	email := claims.Email
	if email == "" {
		email = claims.Mail
	}

	authCtx := map[string]string{
		contextKeyIssuer: claims.Issuer,
	}
	if claims.ClientID != "" {
		authCtx["client_id"] = claims.ClientID
	}

	res := checkResult{
		is:          UNKNOWN,
		subject:     claims.Subject,
		email:       email,
		givenname:   claims.GivenName,
		familyname:  claims.FamilyName,
		groups:      claims.Groups,
		authContext: authCtx,
	}

	// check the policies
	slogctx.Debug(ctx, "Checking policies for JWT",
		"issuer", claims.Issuer,
		"jwksURI", parsed.header.JKU,
		"method", req.method,
		"host", req.host,
		"path", req.path,
	)

	data := map[string]string{
		contextKeyHost:   req.host,
		contextKeyPath:   req.path,
		contextKeyType:   authTypeJWT,
		contextKeyIssuer: claims.Issuer,
		"jwksURI":        parsed.header.JKU,
	}

	allowed, reason, err := srv.policyEngine.Check(
		cedarpolicy.WithSubject(claims.Subject),
		cedarpolicy.WithAction(req.method),
		cedarpolicy.WithContextData(data),
	)
	if err != nil {
		res.is = DENIED
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
// may be either a string or a []any (JSON unmarshals both forms into any).
func firstAudienceString(aud any) string {
	switch v := aud.(type) {
	case string:
		return v
	case []any:
		if len(v) > 0 {
			if s, ok := v[0].(string); ok {
				return s
			}
		}
	}
	return ""
}
