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
		PathPrefix: "/spi/",
		RequiredClaims: []config.RequiredClaim{
			{Field: "ias_apis", Value: "task-center-api", MatchType: config.ClaimMatchTypeContains},
		},
		ClientTypeField:             "sap_id_type",
		ClientTypeMapping:           map[string]string{"app": "TechnicalUser", "user": "User"},
		AdditionalAuthContextFields: []string{"app_tid"},
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
	}{
		{
			name: "no matching prefix falls through to standard check",
			bearerToken: makeToken(jwt.MapClaims{
				"sub":      "std-user",
				"iss":      ts.URL,
				"exp":      exp,
				"mail":     "std@example.com",
				"groups":   []string{"g1"},
				"ias_apis": []string{"task-center-api"},
			}),
			reqPath:  "/cmk/v1/tenant/keys",
			wantCode: ALLOWED,
		},
		{
			name: "matching prefix, requiredClaims contains passes, app token",
			bearerToken: makeToken(jwt.MapClaims{
				"sub":         "app-client",
				"iss":         ts.URL,
				"exp":         exp,
				"email":       "svc@example.com",
				"ias_apis":    []string{"task-center-api", "other-api"},
				"sap_id_type": "app",
				"app_tid":     "tenant-abc",
				"aud":         "client-123",
			}),
			reqPath:        "/spi/tenant1/tasks",
			wantCode:       ALLOWED,
			wantClientType: ptr(clientdata.TechnicalUser),
			wantAppTID:     "tenant-abc",
			wantEmail:      "svc@example.com",
		},
		{
			name: "matching prefix, requiredClaims contains passes, user token",
			bearerToken: makeToken(jwt.MapClaims{
				"sub":         "human-user",
				"iss":         ts.URL,
				"exp":         exp,
				"email":       "human@example.com",
				"ias_apis":    []string{"task-center-api"},
				"sap_id_type": "user",
				"app_tid":     "tenant-xyz",
			}),
			reqPath:        "/spi/tenant1/tasks",
			wantCode:       ALLOWED,
			wantClientType: ptr(clientdata.User),
			wantAppTID:     "tenant-xyz",
			wantEmail:      "human@example.com",
		},
		{
			name: "matching prefix, requiredClaims contains fails - wrong value",
			bearerToken: makeToken(jwt.MapClaims{
				"sub":      "bad-client",
				"iss":      ts.URL,
				"exp":      exp,
				"ias_apis": []string{"other-api"},
			}),
			reqPath:  "/spi/tenant1/tasks",
			wantCode: DENIED,
		},
		{
			name: "matching prefix, requiredClaims contains fails - field missing",
			bearerToken: makeToken(jwt.MapClaims{
				"sub": "no-apis-claim",
				"iss": ts.URL,
				"exp": exp,
			}),
			reqPath:  "/spi/tenant1/tasks",
			wantCode: DENIED,
		},
		{
			name: "matching prefix, clientTypeField value not in mapping leaves override nil",
			bearerToken: makeToken(jwt.MapClaims{
				"sub":         "unknown-type",
				"iss":         ts.URL,
				"exp":         exp,
				"ias_apis":    []string{"task-center-api"},
				"sap_id_type": "service",
			}),
			reqPath:        "/spi/tenant1/tasks",
			wantCode:       ALLOWED,
			wantClientType: nil,
		},
		{
			name: "matching prefix, user_attributes.groups fallback",
			bearerToken: makeToken(jwt.MapClaims{
				"sub":      "grouped-user",
				"iss":      ts.URL,
				"exp":      exp,
				"ias_apis": []string{"task-center-api"},
				"user_attributes": map[string]any{
					"groups": []any{"grpA", "grpB"},
				},
			}),
			reqPath:    "/spi/tenant1/tasks",
			wantCode:   ALLOWED,
			wantGroups: []string{"grpA", "grpB"},
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
	return &ct
}
