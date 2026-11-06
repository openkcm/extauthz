package extauthz

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/openkcm/common-sdk/pkg/oidc"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/code"

	envoyauth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/openkcm/extauthz/internal/clientdata"
	"github.com/openkcm/extauthz/internal/config"
	"github.com/openkcm/extauthz/internal/handler"
	"github.com/openkcm/extauthz/internal/policies/cedarpolicy"
)

func TestCheckJWTToken(t *testing.T) {
	ctx := t.Context()
	// create a JWKS test server
	var (
		wkocResponse []byte
		jwksResponse []byte
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, string(wkocResponse))
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		fmt.Fprintln(w, string(jwksResponse))
	})
	mux.HandleFunc("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"active": true}`)
	})

	ts := httptest.NewTLSServer(mux)
	defer ts.Close()

	// create a JWT token
	exp := time.Now().Add(48 * time.Hour).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":    "me",
		"mail":   "me@my.world",
		"iss":    ts.URL,
		"exp":    exp,
		"groups": []string{"groupA", "groupB"},
	})
	token.Header["kid"] = rsaKeyID
	token.Header["jku"] = ts.URL + "/jwks"

	tokenString, err := token.SignedString(rsaPrivateKey)
	if err != nil {
		t.Fatalf("could not sign token: %s", err)
	}

	// create invalid token
	rsaPrivateKeyInvalid, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("could not generate RSA key: %s", err)
	}

	tokenInvalid := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":    "me",
		"mail":   "me@my.world",
		"iss":    "https://invalid.issuer",
		"exp":    exp,
		"groups": []string{"groupA", "groupB"},
	})
	tokenInvalid.Header["kid"] = rsaKeyID
	tokenInvalid.Header["jku"] = ts.URL + "/jwks"

	tokenStringInvalid, err := tokenInvalid.SignedString(rsaPrivateKeyInvalid)
	if err != nil {
		t.Fatalf("could not sign token: %s", err)
	}

	// create a x509 certificate
	certDER, err := createX509CertDER(time.Now(), time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatalf("could not create x509 certificate: %s", err)
	}

	// create the JWKS response
	eBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(eBytes, uint64(rsaPrivateKey.E))
	eBytes = bytes.TrimLeft(eBytes, "\x00")
	sum := sha256.Sum256(certDER)

	jwksResponse, err = json.Marshal(map[string]any{
		"keys": []map[string]any{{
			"kty":      "RSA",
			"x5t#S256": base64.RawURLEncoding.EncodeToString(sum[:]),
			"e":        base64.RawURLEncoding.EncodeToString(eBytes),
			"use":      "sig",
			"kid":      rsaKeyID,
			"x5c":      []string{base64.StdEncoding.EncodeToString(certDER)},
			"alg":      "RS256",
			"n":        base64.RawURLEncoding.EncodeToString(rsaPrivateKey.N.Bytes()),
		}},
	})
	if err != nil {
		t.Fatalf("could not marshal JWKS response: %s", err)
	}

	wkocResponse, err = json.Marshal(map[string]any{
		"issuer":   ts.URL,
		"jwks_uri": ts.URL + "/jwks",
	})
	if err != nil {
		t.Fatalf("could not marshal WKOC response: %s", err)
	}

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyId"), []byte("key01"), 0644))

	err = createFileWithGeneratedKey(filepath.Join(dir, "key01.pem"))
	require.NoError(t, err)

	// create the test cases
	tests := []struct {
		name        string
		bearerToken string

		wantCheckResultCode checkResultCode
		wantSubject         string
		wantRegion          string
		wantEmail           string
		wantIssuer          string
		wantGroups          []string
		useDenyPolicy       bool
	}{
		{
			name:                "zero values",
			wantCheckResultCode: UNAUTHENTICATED,
		}, {
			name:                "unauthorized",
			bearerToken:         tokenStringInvalid,
			wantCheckResultCode: DENIED,
		}, {
			name:                "authorized",
			bearerToken:         tokenString,
			wantCheckResultCode: ALLOWED,
			wantSubject:         "me",
			wantEmail:           "me@my.world",
			wantIssuer:          ts.URL,
			wantGroups:          []string{"groupA", "groupB"},
		}, {
			name:                "invalid base64 header",
			bearerToken:         "!!!.payload.sig",
			wantCheckResultCode: UNAUTHENTICATED,
		}, {
			// valid base64 but not JSON — exercises the json.Unmarshal error branch
			name:                "header not valid JSON",
			bearerToken:         base64.RawURLEncoding.EncodeToString([]byte("not-json")) + ".payload.sig",
			wantCheckResultCode: UNAUTHENTICATED,
		}, {
			name:                "policy engine denies",
			bearerToken:         tokenString,
			wantCheckResultCode: DENIED,
			wantSubject:         "me",
			wantEmail:           "me@my.world",
			wantGroups:          []string{"groupA", "groupB"},
			useDenyPolicy:       true,
		},
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			// create a provider, which trusts the http test server certificate
			certpool := x509.NewCertPool()
			certpool.AddCert(ts.Certificate())
			cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: certpool}}}

			p, err := oidc.NewProvider(ts.URL, []string{},
				oidc.WithPublicHTTPClient(cl),
				oidc.WithSecureHTTPClient(cl),
			)
			if err != nil {
				t.Fatalf("could not create provider: %s", err)
			}

			hdl, err := handler.NewOIDC(ctx, handler.WithStaticProvider(p))
			if err != nil {
				t.Fatalf("could not create handler: %s", err)
			}

			pe, err := cedarpolicy.NewEngine(cedarpolicy.WithBytes("my policies", []byte(cedarpolicies)))
			if err != nil {
				t.Fatalf("could not create policy engine: %s", err)
			}
			if tc.useDenyPolicy {
				pe, err = cedarpolicy.NewEngine(cedarpolicy.WithBytes("deny all", []byte("")))
				if err != nil {
					t.Fatalf("could not create deny policy engine: %s", err)
				}
			}

			signer, err := clientdata.NewSigner(&commoncfg.FeatureGates{}, &config.ClientData{
				SigningKeyIDFilePath: filepath.Join(dir, "keyId"),
			})
			require.NoError(t, err)

			srv, err := NewServer(
				WithClientDataSigner(signer),
				WithPolicyEngine(pe),
				WithOIDCHandler(hdl),
			)
			if err != nil {
				t.Fatalf("could not create server: %s", err)
			}

			defer func() {
				err = srv.Close()
				if err != nil {
					t.Fatalf("could not stop the server: %s", err)
				}
			}()
			err = srv.Start()
			if err != nil {
				t.Fatalf("could not start the server: %s", err)
			}
			// Act
			result := srv.checkJWTToken(t.Context(), tc.bearerToken, requestInfo{method: "GET", host: "our.service.com", path: "/foo/bar"})

			// Assert
			if result.is != tc.wantCheckResultCode {
				t.Errorf("expected: %v, got: %v", tc.wantCheckResultCode, result.is)
			}

			if result.subject != tc.wantSubject {
				t.Errorf("expected: %v, got: %v", tc.wantSubject, result.subject)
			}

			if result.email != tc.wantEmail {
				t.Errorf("expected: %v, got: %v", tc.wantEmail, result.email)
			}

			if tc.wantIssuer != "" {
				issuer, ok := result.authContext["issuer"]
				if !ok {
					t.Errorf("missing issuer")
				} else {
					if issuer != tc.wantIssuer {
						t.Errorf("expected: %v, got: %v", tc.wantIssuer, issuer)
					}
				}
			}

			if !reflect.DeepEqual(result.groups, tc.wantGroups) {
				t.Errorf("expected: %v, got: %v", tc.wantGroups, result.groups)
			}
		})
	}
}

func TestCheckEnrichedJWTToken(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	var (
		wkocResponse []byte
		jwksResponse []byte
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, string(wkocResponse))
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, string(jwksResponse))
	})
	mux.HandleFunc("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"active": true}`)
	})

	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)

	exp := time.Now().Add(48 * time.Hour).Unix()

	makeToken := func(claims jwt.MapClaims) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = rsaKeyID
		tok.Header["jku"] = ts.URL + "/jwks"
		s, err := tok.SignedString(rsaPrivateKey)
		if err != nil {
			t.Fatalf("could not sign token: %s", err)
		}
		return s
	}

	certDER, err := createX509CertDER(time.Now(), time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatalf("could not create x509 certificate: %s", err)
	}
	eBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(eBytes, uint64(rsaPrivateKey.E))
	eBytes = bytes.TrimLeft(eBytes, "\x00")
	sum := sha256.Sum256(certDER)

	jwksResponse, err = json.Marshal(map[string]any{
		"keys": []map[string]any{{
			"kty":      "RSA",
			"x5t#S256": base64.RawURLEncoding.EncodeToString(sum[:]),
			"e":        base64.RawURLEncoding.EncodeToString(eBytes),
			"use":      "sig",
			"kid":      rsaKeyID,
			"x5c":      []string{base64.StdEncoding.EncodeToString(certDER)},
			"alg":      "RS256",
			"n":        base64.RawURLEncoding.EncodeToString(rsaPrivateKey.N.Bytes()),
		}},
	})
	if err != nil {
		t.Fatalf("could not marshal JWKS response: %s", err)
	}
	wkocResponse, err = json.Marshal(map[string]any{
		"issuer":   ts.URL,
		"jwks_uri": ts.URL + "/jwks",
	})
	if err != nil {
		t.Fatalf("could not marshal WKOC response: %s", err)
	}

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyId"), []byte("key01"), 0644))
	require.NoError(t, createFileWithGeneratedKey(filepath.Join(dir, "key01.pem")))

	rule := config.JWTPathPrefixRule{
		PathPrefix: "/api/",
		RequiredClaims: []config.RequiredClaim{
			{Field: "scope", Value: "my-api", MatchType: config.ClaimMatchTypeContains},
		},
		ClientTypeField:             "id_type",
		ClientTypeMapping:           map[string]string{"app": string(clientdata.TechnicalUser), "user": string(clientdata.User)},
		AdditionalAuthContextFields: map[string]string{"app_tid": "app_tid"},
	}

	tests := []struct {
		name           string
		bearerToken    string
		reqPath        string
		wantCode       checkResultCode
		wantClientType *clientdata.ClientType
		wantAppTID     string
		wantGroups     []string
		wantEmail      string
		useDenyPolicy  bool
	}{
		{
			name: "no matching prefix falls through to standard check",
			bearerToken: makeToken(jwt.MapClaims{
				"sub":    "std-user",
				"iss":    ts.URL,
				"exp":    exp,
				"mail":   "std@example.com",
				"groups": []string{"g1"},
				"scope":  []string{"my-api"},
			}),
			reqPath:  "/cmk/v1/tenant/keys",
			wantCode: ALLOWED,
		},
		{
			name: "matching prefix, requiredClaims contains passes, app token",
			bearerToken: makeToken(jwt.MapClaims{
				"sub":     "app-client",
				"iss":     ts.URL,
				"exp":     exp,
				"email":   "svc@example.com",
				"scope":   []string{"my-api", "other-api"},
				"id_type": "app",
				"app_tid": "tenant-abc",
				"aud":     "client-123",
			}),
			reqPath:        "/api/tenant1/items",
			wantCode:       ALLOWED,
			wantClientType: ptr(clientdata.TechnicalUser),
			wantAppTID:     "tenant-abc",
			wantEmail:      "svc@example.com",
		},
		{
			name: "matching prefix, requiredClaims contains passes, user token",
			bearerToken: makeToken(jwt.MapClaims{
				"sub":     "human-user",
				"iss":     ts.URL,
				"exp":     exp,
				"email":   "human@example.com",
				"scope":   []string{"my-api"},
				"id_type": "user",
				"app_tid": "tenant-xyz",
			}),
			reqPath:        "/api/tenant1/items",
			wantCode:       ALLOWED,
			wantClientType: ptr(clientdata.User),
			wantAppTID:     "tenant-xyz",
			wantEmail:      "human@example.com",
		},
		{
			name: "matching prefix, requiredClaims contains fails - wrong value",
			bearerToken: makeToken(jwt.MapClaims{
				"sub":   "bad-client",
				"iss":   ts.URL,
				"exp":   exp,
				"scope": []string{"other-api"},
			}),
			reqPath:  "/api/tenant1/items",
			wantCode: DENIED,
		},
		{
			name: "matching prefix, requiredClaims contains fails - field missing",
			bearerToken: makeToken(jwt.MapClaims{
				"sub": "no-scope-claim",
				"iss": ts.URL,
				"exp": exp,
			}),
			reqPath:  "/api/tenant1/items",
			wantCode: DENIED,
		},
		{
			name: "matching prefix, clientTypeField value not in mapping leaves override nil",
			bearerToken: makeToken(jwt.MapClaims{
				"sub":     "unknown-type",
				"iss":     ts.URL,
				"exp":     exp,
				"scope":   []string{"my-api"},
				"id_type": "service",
			}),
			reqPath:        "/api/tenant1/items",
			wantCode:       ALLOWED,
			wantClientType: nil,
		},
		{
			name:        "not a JWT token (missing dots)",
			bearerToken: "notavalidtoken",
			reqPath:     "/api/tenant1/items",
			wantCode:    UNAUTHENTICATED,
		},
		{
			name:        "invalid base64 in header",
			bearerToken: "!!!.payload.sig",
			reqPath:     "/api/tenant1/items",
			wantCode:    UNAUTHENTICATED,
		},
		{
			name:        "header not valid JSON",
			bearerToken: base64.RawURLEncoding.EncodeToString([]byte("not-json")) + ".payload.sig",
			reqPath:     "/api/tenant1/items",
			wantCode:    UNAUTHENTICATED,
		},
		{
			name: "policy engine denies",
			bearerToken: makeToken(jwt.MapClaims{
				"sub":   "denied-user",
				"iss":   ts.URL,
				"exp":   exp,
				"scope": []string{"my-api"},
			}),
			reqPath:  "/api/tenant1/items",
			wantCode: DENIED,
			// uses a deny-all policy engine, set via policyOverride in the test loop
			useDenyPolicy: true,
		},
		{
			name: "missing sub claim is denied",
			bearerToken: makeToken(jwt.MapClaims{
				"iss":   ts.URL,
				"exp":   exp,
				"scope": []string{"my-api"},
			}),
			reqPath:  "/api/tenant1/items",
			wantCode: DENIED,
		},
		{
			name: "empty sub claim is denied",
			bearerToken: makeToken(jwt.MapClaims{
				"sub":   "",
				"iss":   ts.URL,
				"exp":   exp,
				"scope": []string{"my-api"},
			}),
			reqPath:  "/api/tenant1/items",
			wantCode: DENIED,
		},
		{
			name: "exact path without trailing slash matches rule",
			bearerToken: makeToken(jwt.MapClaims{
				"sub":   "app-client",
				"iss":   ts.URL,
				"exp":   exp,
				"scope": []string{"my-api"},
			}),
			reqPath:  "/api",
			wantCode: ALLOWED,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			certpool := x509.NewCertPool()
			certpool.AddCert(ts.Certificate())
			cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: certpool}}}

			p, err := oidc.NewProvider(ts.URL, []string{},
				oidc.WithPublicHTTPClient(cl),
				oidc.WithSecureHTTPClient(cl),
			)
			require.NoError(t, err)

			hdl, err := handler.NewOIDC(ctx, handler.WithStaticProvider(p))
			require.NoError(t, err)

			pe, err := cedarpolicy.NewEngine(cedarpolicy.WithBytes("my policies", []byte("permit(principal, action, resource);")))
			require.NoError(t, err)

			if tc.useDenyPolicy {
				pe, err = cedarpolicy.NewEngine(cedarpolicy.WithBytes("deny all", []byte("")))
				require.NoError(t, err)
			}

			signer, err := clientdata.NewSigner(&commoncfg.FeatureGates{}, &config.ClientData{
				SigningKeyIDFilePath: filepath.Join(dir, "keyId"),
			})
			require.NoError(t, err)

			srv, err := NewServer(
				WithClientDataSigner(signer),
				WithPolicyEngine(pe),
				WithOIDCHandler(hdl),
				WithJWTPathPrefixRules([]config.JWTPathPrefixRule{rule}),
			)
			require.NoError(t, err)
			defer func() { require.NoError(t, srv.Close()) }()
			require.NoError(t, srv.Start())

			result := srv.checkJWTToken(t.Context(), tc.bearerToken, requestInfo{
				method: "GET",
				host:   "our.service.com",
				path:   tc.reqPath,
			})

			require.Equal(t, tc.wantCode, result.is, "check result code")

			if tc.wantClientType != nil {
				require.NotNil(t, result.clientTypeOverride)
				require.Equal(t, *tc.wantClientType, *result.clientTypeOverride)
			} else {
				require.Nil(t, result.clientTypeOverride, "expected no client type override")
			}

			if tc.wantAppTID != "" {
				require.Equal(t, tc.wantAppTID, result.authContext["app_tid"])
			}

			if tc.wantEmail != "" {
				require.Equal(t, tc.wantEmail, result.email)
			}

			if tc.wantGroups != nil {
				require.Equal(t, tc.wantGroups, result.groups)
			}
		})
	}
}

// ptr returns a pointer to a clientdata.ClientType value.
func ptr(ct clientdata.ClientType) *clientdata.ClientType {
	p := new(clientdata.ClientType)
	*p = ct
	return p
}

// TestPathNormalizationBypassPrevention verifies that paths with double-slashes
// or dot-segments cannot bypass JWT prefix rules. It calls srv.Check()
// end-to-end so that removing path.Clean from check.go causes the tests to fail.
func TestPathNormalizationBypassPrevention(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	var (
		wkocResponse []byte
		jwksResponse []byte
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, string(wkocResponse))
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, string(jwksResponse))
	})
	mux.HandleFunc("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"active": true}`)
	})

	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)

	exp := time.Now().Add(48 * time.Hour).Unix()

	makeToken := func(claims jwt.MapClaims) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = rsaKeyID
		s, err := tok.SignedString(rsaPrivateKey)
		require.NoError(t, err)
		return s
	}

	jwksBytes, err := json.Marshal(map[string]any{
		"keys": []map[string]any{{"kty": "RSA", "kid": rsaKeyID, "use": "sig", "n": base64.RawURLEncoding.EncodeToString(rsaPublicKey.N.Bytes()), "e": func() string {
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, uint32(rsaPublicKey.E))
			return base64.RawURLEncoding.EncodeToString(bytes.TrimLeft(b, "\x00"))
		}()}},
	})
	require.NoError(t, err)
	jwksResponse = jwksBytes

	wkocResponse, err = json.Marshal(map[string]any{
		"issuer":   ts.URL,
		"jwks_uri": ts.URL + "/jwks",
	})
	require.NoError(t, err)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyId"), []byte("key01"), 0644))
	require.NoError(t, createFileWithGeneratedKey(filepath.Join(dir, "key01.pem")))

	certpool := x509.NewCertPool()
	certpool.AddCert(ts.Certificate())
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: certpool}}}

	p, err := oidc.NewProvider(ts.URL, []string{},
		oidc.WithPublicHTTPClient(cl),
		oidc.WithSecureHTTPClient(cl),
	)
	require.NoError(t, err)

	hdl, err := handler.NewOIDC(ctx, handler.WithStaticProvider(p))
	require.NoError(t, err)

	pe, err := cedarpolicy.NewEngine(cedarpolicy.WithBytes("permit all", []byte("permit(principal, action, resource);")))
	require.NoError(t, err)

	signer, err := clientdata.NewSigner(&commoncfg.FeatureGates{}, &config.ClientData{
		SigningKeyIDFilePath: filepath.Join(dir, "keyId"),
	})
	require.NoError(t, err)

	// Rule requires scope claim containing "api:read" on paths under /api/v2/.
	// Without path normalization, /api//v2/items has /api/ as a naive prefix but
	// NOT /api/v2/ — so the rule would be skipped, scope enforcement bypassed,
	// and the request allowed. With normalization it cleans to /api/v2/items,
	// matches the rule, and the missing scope claim causes DENIED.
	srv, err := NewServer(
		WithClientDataSigner(signer),
		WithPolicyEngine(pe),
		WithOIDCHandler(hdl),
		WithJWTPathPrefixRules([]config.JWTPathPrefixRule{{
			PathPrefix: "/api/v2/",
			RequiredClaims: []config.RequiredClaim{
				{Field: "scope", Value: "api:read", MatchType: config.ClaimMatchTypeContains},
			},
		}}),
	)
	require.NoError(t, err)
	defer func() { require.NoError(t, srv.Close()) }()
	require.NoError(t, srv.Start())

	// Token without the required scope claim.
	tokenWithoutClaim := makeToken(jwt.MapClaims{
		"sub": "attacker",
		"iss": ts.URL,
		"exp": exp,
	})

	makeRequest := func(path string) *envoyauth.CheckRequest {
		return &envoyauth.CheckRequest{
			Attributes: &envoyauth.AttributeContext{
				Request: &envoyauth.AttributeContext_Request{
					Http: &envoyauth.AttributeContext_HttpRequest{
						Method:  "GET",
						Host:    "our.service.com",
						Path:    path,
						Headers: map[string]string{"authorization": "Bearer " + tokenWithoutClaim},
					},
				},
			},
		}
	}

	t.Run("double-slash path does not bypass prefix rule", func(t *testing.T) {
		t.Parallel()
		// /api//v2/items normalizes to /api/v2/items, which matches /api/v2/ rule.
		// The missing scope claim must produce DENIED, not ALLOWED.
		resp, err := srv.Check(ctx, makeRequest("/api//v2/items"))
		require.NoError(t, err)
		require.Equal(t, int32(code.Code_PERMISSION_DENIED), resp.GetStatus().GetCode(),
			"double-slash path must not bypass the /api/v2/ prefix rule")
	})

	t.Run("dot-segment path does not bypass prefix rule", func(t *testing.T) {
		t.Parallel()
		// /api/./v2/items does NOT start with /api/v2/ as a raw string, so without
		// normalization the rule would be skipped and the request allowed. With
		// path.Clean it normalizes to /api/v2/items, the rule fires, and the missing
		// scope claim produces DENIED.
		resp, err := srv.Check(ctx, makeRequest("/api/./v2/items"))
		require.NoError(t, err)
		require.Equal(t, int32(code.Code_PERMISSION_DENIED), resp.GetStatus().GetCode(),
			"dot-segment path must not bypass the /api/v2/ prefix rule")
	})
}

func TestJWTValidationError(t *testing.T) {
	t.Parallel()
	// parts[0]=header, parts[1]=payload — safe to log, never parts[2] (signature)
	parsed := parsedJWTHeader{parts: []string{"aGVhZGVy", "cGF5bG9hZA", "c2ln"}, ok: true}
	tests := []struct {
		name     string
		err      error
		wantCode checkResultCode
		wantInfo string
	}{
		{"ErrInvalidToken", handler.ErrInvalidToken, UNAUTHENTICATED, "Invalid authorization header"},
		{"ErrNoProvider", handler.ErrNoProvider, DENIED, "No provider found"},
		{"generic error", errors.New("something went wrong"), UNAUTHENTICATED, "Error from JWT validation: something went wrong"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := jwtValidationError(t.Context(), tc.err, parsed)
			require.Equal(t, tc.wantCode, result.is)
			require.Equal(t, tc.wantInfo, result.info)
		})
	}
}

func TestFirstAudienceString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		aud  any
		want string
	}{
		{"string value", "my-client", "my-client"},
		{"array first element", []any{"first", "second"}, "first"},
		{"empty array", []any{}, ""},
		{"array with non-string first", []any{42, "second"}, ""},
		{"nil", nil, ""},
		{"int", 42, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, firstAudienceString(tc.aud))
		})
	}
}

func TestExtractGroups(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		rawClaims map[string]any
		want      []string
	}{
		{
			name:      "groups claim present",
			rawClaims: map[string]any{"groups": []any{"g1", "g2"}},
			want:      []string{"g1", "g2"},
		},
		{
			name:      "no groups anywhere",
			rawClaims: map[string]any{},
			want:      nil,
		},
		{
			name:      "groups contains non-string values skipped",
			rawClaims: map[string]any{"groups": []any{"valid", 42, "also-valid"}},
			want:      []string{"valid", "also-valid"},
		},
		{
			name:      "empty groups array returns nil",
			rawClaims: map[string]any{"groups": []any{}},
			want:      nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, extractGroups(tc.rawClaims))
		})
	}
}

func TestBuildAuthContext(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		issuer           string
		rawClaims        map[string]any
		additionalFields map[string]string
		want             map[string]string
	}{
		{
			name:   "issuer always present",
			issuer: "https://issuer.example",
			want:   map[string]string{"issuer": "https://issuer.example"},
		},
		{
			name:      "aud claim does not set client_id",
			issuer:    "iss",
			rawClaims: map[string]any{"aud": "my-client"},
			want:      map[string]string{"issuer": "iss"},
		},
		{
			name:      "client_id claim sets client_id",
			issuer:    "iss",
			rawClaims: map[string]any{"client_id": "my-client"},
			want:      map[string]string{"issuer": "iss", "client_id": "my-client"},
		},
		{
			name:             "additional field copied",
			issuer:           "iss",
			rawClaims:        map[string]any{"tid": "tenant-123"},
			additionalFields: map[string]string{"tid": "tenant_id"},
			want:             map[string]string{"issuer": "iss", "tenant_id": "tenant-123"},
		},
		{
			name:             "reserved output key issuer skipped",
			issuer:           "iss",
			rawClaims:        map[string]any{"x": "val"},
			additionalFields: map[string]string{"x": "issuer"},
			want:             map[string]string{"issuer": "iss"},
		},
		{
			name:             "reserved output key client_id skipped",
			issuer:           "iss",
			rawClaims:        map[string]any{"x": "val"},
			additionalFields: map[string]string{"x": "client_id"},
			want:             map[string]string{"issuer": "iss"},
		},
		{
			name:             "empty claim value not copied",
			issuer:           "iss",
			rawClaims:        map[string]any{"tid": ""},
			additionalFields: map[string]string{"tid": "tenant_id"},
			want:             map[string]string{"issuer": "iss"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := buildAuthContext(tc.issuer, tc.rawClaims, tc.additionalFields)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestValidateRequiredClaims(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		rawClaims map[string]any
		rules     []config.RequiredClaim
		wantDeny  bool
		wantInfo  string
	}{
		{
			name:      "no rules always passes",
			rawClaims: map[string]any{},
			wantDeny:  false,
		},
		{
			name:      "equals match passes",
			rawClaims: map[string]any{"scope": "read"},
			rules:     []config.RequiredClaim{{Field: "scope", Value: "read", MatchType: config.ClaimMatchTypeEquals}},
			wantDeny:  false,
		},
		{
			name:      "equals match fails wrong value",
			rawClaims: map[string]any{"scope": "write"},
			rules:     []config.RequiredClaim{{Field: "scope", Value: "read", MatchType: config.ClaimMatchTypeEquals}},
			wantDeny:  true,
			wantInfo:  `required claim "scope" does not equal "read"`,
		},
		{
			name:      "equals match fails non-string claim",
			rawClaims: map[string]any{"scope": 42},
			rules:     []config.RequiredClaim{{Field: "scope", Value: "read", MatchType: config.ClaimMatchTypeEquals}},
			wantDeny:  true,
			wantInfo:  `required claim "scope" does not equal "read"`,
		},
		{
			name:      "contains match passes",
			rawClaims: map[string]any{"roles": []any{"admin", "user"}},
			rules:     []config.RequiredClaim{{Field: "roles", Value: "admin", MatchType: config.ClaimMatchTypeContains}},
			wantDeny:  false,
		},
		{
			name:      "contains match fails missing value",
			rawClaims: map[string]any{"roles": []any{"user"}},
			rules:     []config.RequiredClaim{{Field: "roles", Value: "admin", MatchType: config.ClaimMatchTypeContains}},
			wantDeny:  true,
			wantInfo:  `required claim "roles" does not contain "admin"`,
		},
		{
			name:      "contains match fails non-array claim",
			rawClaims: map[string]any{"roles": "admin"},
			rules:     []config.RequiredClaim{{Field: "roles", Value: "admin", MatchType: config.ClaimMatchTypeContains}},
			wantDeny:  true,
			wantInfo:  `required claim "roles" is not an array`,
		},
		{
			name:      "field missing",
			rawClaims: map[string]any{},
			rules:     []config.RequiredClaim{{Field: "roles", Value: "admin", MatchType: config.ClaimMatchTypeContains}},
			wantDeny:  true,
			wantInfo:  `required claim "roles" is missing`,
		},
		{
			name:      "unknown match type denied",
			rawClaims: map[string]any{"x": "y"},
			rules:     []config.RequiredClaim{{Field: "x", Value: "y", MatchType: "unknown"}},
			wantDeny:  true,
			wantInfo:  `required claim "x" has unknown match type "unknown"`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result, deny := validateRequiredClaims(tc.rawClaims, tc.rules)
			require.Equal(t, tc.wantDeny, deny)
			if tc.wantDeny {
				require.Equal(t, DENIED, result.is)
				require.Equal(t, tc.wantInfo, result.info)
			}
		})
	}
}

func TestDeriveClientTypeOverride(t *testing.T) {
	t.Parallel()
	rule := config.JWTPathPrefixRule{
		ClientTypeField: "id_type",
		ClientTypeMapping: map[string]string{
			"app": string(clientdata.TechnicalUser),
			"svc": string(clientdata.System),
			"usr": string(clientdata.User),
		},
	}
	tests := []struct {
		name      string
		rawClaims map[string]any
		rule      config.JWTPathPrefixRule
		want      *clientdata.ClientType
	}{
		{"no ClientTypeField", map[string]any{"id_type": "app"}, config.JWTPathPrefixRule{}, nil},
		{"field absent in claims", map[string]any{}, rule, nil},
		{"field value not in mapping", map[string]any{"id_type": "unknown"}, rule, nil},
		{"maps to TechnicalUser", map[string]any{"id_type": "app"}, rule, ptr(clientdata.TechnicalUser)},
		{"maps to System", map[string]any{"id_type": "svc"}, rule, ptr(clientdata.System)},
		{"maps to User", map[string]any{"id_type": "usr"}, rule, ptr(clientdata.User)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := deriveClientTypeOverride(tc.rawClaims, tc.rule)
			if tc.want == nil {
				require.Nil(t, got)
			} else {
				require.NotNil(t, got)
				require.Equal(t, *tc.want, *got)
			}
		})
	}
}
