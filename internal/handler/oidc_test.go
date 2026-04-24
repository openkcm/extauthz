package handler

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/openkcm/common-sdk/pkg/oidc"
	"github.com/stretchr/testify/assert"
)

func TestNewOIDC(t *testing.T) {
	ctx := t.Context()
	t.Run("no panic with nil options", func(t *testing.T) {
		assert.NotPanics(t, func() {
			//nolint:errcheck
			NewOIDC(ctx, nil)
		})
	})

	const providerUrl = "https://example.com"

	staticProvider, err := oidc.NewProvider(providerUrl, []string{"aud1"})
	if err != nil {
		t.Fatalf("could not create static provider: %s", err)
	}

	// create the test cases
	tests := []struct {
		name      string
		opts      []OIDCOption
		checkFunc func(*OIDC) error
		wantError bool
	}{
		{
			name: "zero values",
		}, {
			name: "with signing key cache expiration",
			opts: []OIDCOption{
				WithSigningKeyCacheExpiration(30 * time.Second),
			},
		}, {
			name: "with cache expiration",
			opts: []OIDCOption{
				WithIntrospectionCacheExpiration(30 * time.Second),
			},
		}, {
			name: "with issuer claim keys iss",
			opts: []OIDCOption{
				WithIssuerClaimKeys(oidc.DefaultIssuerClaims...),
			},
			checkFunc: issuerClaimHandler("iss"),
		}, {
			name: "with issuer claim keys ias_iss",
			opts: []OIDCOption{
				WithIssuerClaimKeys("ias_iss"),
			},
			checkFunc: issuerClaimHandler("ias_iss"),
		}, {
			name: "with nil provider",
			opts: []OIDCOption{
				WithStaticProvider(nil),
			},
			wantError: true,
		}, {
			name: "with provider storing by issuer",
			opts: []OIDCOption{
				WithStaticProvider(staticProvider),
			},
			checkFunc: func(h *OIDC) error {
				key := providerUrl
				if _, found := h.staticProviders[key]; !found {
					return errors.New("expected providers to be initialized")
				}
				return nil
			},
		},
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			// manager := NewM

			// Act
			hdl, err := NewOIDC(ctx, tc.opts...)
			if tc.checkFunc != nil {
				err = tc.checkFunc(hdl)
			}

			// Assert
			if tc.wantError {
				if err == nil {
					t.Error("expected error, but got nil")
				}

				if hdl != nil {
					t.Errorf("expected nil handler, but got: %v", hdl)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %s", err)
				}
			}
		})
	}
}

func TestParseAndValidate(t *testing.T) {
	ctx := t.Context()
	// create a JWKS test server
	var (
		wkocResponse  []byte
		jwksResponse  []byte
		introspection []byte
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
		fmt.Fprintln(w, string(introspection))
	})

	httpTestServer := httptest.NewServer(mux)
	defer httpTestServer.Close()
	httpsTestServer := httptest.NewTLSServer(mux)
	defer httpsTestServer.Close()

	// create an RSA key pair
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("could not generate RSA key: %s", err)
	}

	rsaPublicKey := &rsaPrivateKey.PublicKey
	rsaKeyID := uuid.Must(uuid.NewV4()).String()

	// create a x509 certificate
	cert := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"KMS, Inc"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(5 * time.Minute),
	}

	x509Cert, err := x509.CreateCertificate(rand.Reader, &cert, &cert, rsaPublicKey, rsaPrivateKey)
	if err != nil {
		t.Fatalf("could not create x509 certificate: %s", err)
	}

	// create the JWKS response
	eBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(eBytes, uint64(rsaPrivateKey.E))
	eBytes = bytes.TrimLeft(eBytes, "\x00")
	sum := sha256.Sum256(x509Cert)

	jwksResponse, err = json.Marshal(map[string]any{
		"keys": []map[string]any{{
			"kty":      "RSA",
			"x5t#S256": base64.RawURLEncoding.EncodeToString(sum[:]),
			"e":        base64.RawURLEncoding.EncodeToString(eBytes),
			"use":      "sig",
			"kid":      rsaKeyID,
			"x5c":      []string{base64.StdEncoding.EncodeToString(x509Cert)},
			"alg":      "RS256",
			"n":        base64.RawURLEncoding.EncodeToString(rsaPrivateKey.N.Bytes()),
		}},
	})
	if err != nil {
		t.Fatalf("could not marshal JWKS response: %s", err)
	}

	wkocResponse, err = json.Marshal(map[string]any{
		"issuer":                 httpsTestServer.URL,
		"jwks_uri":               httpsTestServer.URL + "/jwks",
		"introspection_endpoint": httpsTestServer.URL + "/oauth2/introspect",
	})
	if err != nil {
		t.Fatalf("could not marshal WKOC response: %s", err)
	}

	// create the test cases
	tests := []struct {
		name            string
		issuerClaimKeys []string
		jwksURI         string
		token           *jwt.Token
		providerOptions []oidc.ProviderOption
		featureGates    *commoncfg.FeatureGates
		introspection   []byte
		wantError       bool
	}{
		{
			name:            "zero values",
			issuerClaimKeys: oidc.DefaultIssuerClaims,
			wantError:       true,
		}, {
			name:            "invalid token: wrong IAS issuer",
			issuerClaimKeys: []string{"ias_iss"},
			jwksURI:         "https://invalid.issuer/jwks",
			token: jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub":     "me",
				"mail":    "me@my.world",
				"ias_iss": "https://invalid.issuer",
				"exp":     time.Now().Add(48 * time.Hour).Unix(),
				"aud":     []string{"aud1"},
			}),
			wantError: true,
		}, {
			name:            "invalid token: wrong issuer",
			issuerClaimKeys: oidc.DefaultIssuerClaims,
			jwksURI:         "https://invalid.issuer/jwks",
			token: jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub":  "me",
				"mail": "me@my.world",
				"iss":  "https://invalid.issuer",
				"exp":  time.Now().Add(48 * time.Hour).Unix(),
				"aud":  []string{"aud1"},
			}),
			wantError: true,
		}, {
			name:            "invalid token: wrong issuer scheme",
			issuerClaimKeys: oidc.DefaultIssuerClaims,
			token: jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub":  "me",
				"mail": "me@my.world",
				"iss":  httpsTestServer.URL,
				"exp":  time.Now().Add(48 * time.Hour).Unix(),
			}),
			wantError: true,
		}, {
			name:            "invalid token: no audience",
			issuerClaimKeys: oidc.DefaultIssuerClaims,
			token: jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub":  "me",
				"mail": "me@my.world",
				"iss":  httpsTestServer.URL,
				"exp":  time.Now().Add(48 * time.Hour).Unix(),
			}),
			wantError: true,
		}, {
			name:            "invalid token: wrong audience",
			issuerClaimKeys: oidc.DefaultIssuerClaims,
			token: jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub":  "me",
				"mail": "me@my.world",
				"iss":  httpsTestServer.URL,
				"exp":  time.Now().Add(48 * time.Hour).Unix(),
				"aud":  []string{"vip"},
			}),
			wantError: true,
		}, {
			name:            "invalid token: not before",
			issuerClaimKeys: oidc.DefaultIssuerClaims,
			token: jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub":  "me",
				"mail": "me@my.world",
				"iss":  httpsTestServer.URL,
				"nbf":  time.Now().Add(24 * time.Hour).Unix(),
				"exp":  time.Now().Add(48 * time.Hour).Unix(),
				"aud":  []string{"aud1", "aud2"},
			}),
			wantError: true,
		}, {
			name:            "invalid token: expired",
			issuerClaimKeys: oidc.DefaultIssuerClaims,
			token: jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub":  "me",
				"mail": "me@my.world",
				"iss":  httpsTestServer.URL,
				"exp":  time.Now().Add(-48 * time.Hour).Unix(),
				"aud":  []string{"aud1", "aud2"},
			}),
			wantError: true,
		}, {
			name:            "invalid token: no expiry",
			issuerClaimKeys: oidc.DefaultIssuerClaims,
			token: jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub":  "me",
				"mail": "me@my.world",
				"iss":  httpsTestServer.URL,
				"aud":  []string{"aud1", "aud2"},
			}),
			wantError: true,
		}, {
			name:            "valid token",
			issuerClaimKeys: oidc.DefaultIssuerClaims,
			token: jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub":  "me",
				"mail": "me@my.world",
				"iss":  httpsTestServer.URL,
				"exp":  time.Now().Add(48 * time.Hour).Unix(),
				"aud":  []string{"aud1", "aud2"},
			}),
			wantError: false,
		}, {
			name:            "valid IAS token with ias_iss",
			issuerClaimKeys: []string{"ias_iss"},
			token: jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub":     "me",
				"mail":    "me@my.world",
				"ias_iss": httpsTestServer.URL,
				"exp":     time.Now().Add(48 * time.Hour).Unix(),
				"aud":     []string{"aud1", "aud2"},
			}),
			wantError: false,
		}, {
			name:            "valid IAS token with iss",
			issuerClaimKeys: oidc.DefaultIssuerClaims,
			token: jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub":  "me",
				"mail": "me@my.world",
				"iss":  httpsTestServer.URL,
				"exp":  time.Now().Add(48 * time.Hour).Unix(),
				"aud":  []string{"aud1", "aud2"},
			}),
			wantError: false,
		}, {
			name:            "revoked token",
			issuerClaimKeys: oidc.DefaultIssuerClaims,
			token: jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub":  "me",
				"mail": "me@my.world",
				"iss":  httpsTestServer.URL,
				"exp":  time.Now().Add(48 * time.Hour).Unix(),
				"aud":  []string{"aud1", "aud2"},
			}),
			providerOptions: []oidc.ProviderOption{},
			introspection:   []byte(`{"active": false}`),
			wantError:       true,
		}, {
			name:            "Active token",
			issuerClaimKeys: oidc.DefaultIssuerClaims,
			token: jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub":  "me",
				"mail": "me@my.world",
				"iss":  httpsTestServer.URL,
				"exp":  time.Now().Add(48 * time.Hour).Unix(),
				"aud":  []string{"aud1", "aud2"},
			}),
			providerOptions: []oidc.ProviderOption{},
			wantError:       false,
		},
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange

			// create a provider, which trusts the test server certificate
			certpool := x509.NewCertPool()
			certpool.AddCert(httpsTestServer.Certificate())
			cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: certpool}}}
			providerOpts := append([]oidc.ProviderOption{
				oidc.WithPublicHTTPClient(cl),
				oidc.WithSecureHTTPClient(cl),
			}, tc.providerOptions...)
			provider, err := oidc.NewProvider(httpsTestServer.URL, []string{"aud1"}, providerOpts...)
			if err != nil {
				t.Fatalf("could not create https provider: %s", err)
			}
			handlerOpts := []OIDCOption{
				WithIssuerClaimKeys(tc.issuerClaimKeys...),
				WithStaticProvider(provider),
			}
			if tc.featureGates != nil {
				handlerOpts = append(handlerOpts, WithFeatureGates(tc.featureGates))
			}
			hdl, err := NewOIDC(ctx, handlerOpts...)
			if err != nil {
				t.Fatalf("could not create handler: %s", err)
			}

			introspection = []byte(`{"active": true}`)
			if tc.introspection != nil {
				introspection = tc.introspection
			}

			claims := struct {
				Subject  string   `json:"sub"`
				EMail    string   `json:"mail"`
				Audience []string `json:"aud"`
			}{}

			var tokenString string

			if tc.token != nil {
				token := tc.token
				token.Header["kid"] = rsaKeyID
				token.Header["jku"] = httpsTestServer.URL + "/jwks"

				tokenString, err = token.SignedString(rsaPrivateKey)
				if err != nil {
					t.Fatalf("could not sign token: %s", err)
				}
			}

			// Act
			err = hdl.ParseAndValidate(t.Context(), tokenString, "", &claims, false)

			// Assert
			if tc.wantError {
				if err == nil {
					t.Error("expected error, but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %s", err)
				}
			}
		})
	}
}

func issuerClaimHandler(claimKey string) func(h *OIDC) error {
	return func(h *OIDC) error {
		found := false

		for _, key := range h.issuerClaimKeys {
			if key == claimKey {
				found = true
			}
		}

		if !found {
			return fmt.Errorf("expected %s into issuer claim keys", claimKey)
		}

		return nil
	}
}

func TestExtractFromClaims(t *testing.T) {
	tests := []struct {
		name     string
		claims   map[string]any
		keys     []string
		expected string
	}{
		{
			name:     "empty claims",
			claims:   map[string]any{},
			keys:     []string{"iss"},
			expected: "",
		},
		{
			name:     "key exists with string value",
			claims:   map[string]any{"iss": "https://example.com"},
			keys:     []string{"iss"},
			expected: "https://example.com",
		},
		{
			name:     "key exists with non-string value",
			claims:   map[string]any{"iss": 12345},
			keys:     []string{"iss"},
			expected: "",
		},
		{
			name:     "first key not found, second key found",
			claims:   map[string]any{"ias_iss": "https://example.com"},
			keys:     []string{"iss", "ias_iss"},
			expected: "https://example.com",
		},
		{
			name:     "no keys provided",
			claims:   map[string]any{"iss": "https://example.com"},
			keys:     []string{},
			expected: "",
		},
		{
			name:     "key exists with nil value",
			claims:   map[string]any{"iss": nil},
			keys:     []string{"iss"},
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractFromClaims(tc.claims, tc.keys...)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestProviderFor(t *testing.T) {
	ctx := t.Context()
	const (
		issuer   = "https://example.com"
		jwksURI  = "https://example.com/jwks"
		tenantID = "tenant-123"
	)

	// Create static providers for testing
	staticProviderByIssuer, err := oidc.NewProvider(issuer, []string{"aud1"})
	if err != nil {
		t.Fatalf("could not create static provider: %s", err)
	}

	staticProviderByJwksURI, err := oidc.NewProvider(issuer, []string{"aud1"}, oidc.WithCustomJWKSURI(jwksURI))
	if err != nil {
		t.Fatalf("could not create static provider with custom jwks uri: %s", err)
	}

	tests := []struct {
		name          string
		setupHandler  func() *OIDC
		issuer        string
		jwksURI       string
		tenantID      string
		expectError   bool
		errorContains string
	}{
		{
			name: "static provider found by issuer",
			setupHandler: func() *OIDC {
				h, _ := NewOIDC(ctx, WithStaticProvider(staticProviderByIssuer))
				return h
			},
			issuer:      issuer,
			jwksURI:     "",
			expectError: false,
		},
		{
			name: "static provider found by jwksURI",
			setupHandler: func() *OIDC {
				h, _ := NewOIDC(ctx, WithStaticProvider(staticProviderByJwksURI))
				return h
			},
			issuer:      issuer,
			jwksURI:     jwksURI,
			expectError: false,
		},
		{
			name: "no static provider and no session manager",
			setupHandler: func() *OIDC {
				h, _ := NewOIDC(ctx)
				return h
			},
			issuer:        issuer,
			jwksURI:       "",
			expectError:   true,
			errorContains: "no provider found",
		},
		{
			name: "jwksURI matches but issuer doesn't match",
			setupHandler: func() *OIDC {
				h, _ := NewOIDC(ctx, WithStaticProvider(staticProviderByJwksURI))
				return h
			},
			issuer:        "https://other-issuer.com",
			jwksURI:       jwksURI,
			expectError:   true,
			errorContains: "no provider found",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := tc.setupHandler()
			provider, err := handler.ProviderFor(t.Context(), tc.issuer, tc.jwksURI, tc.tenantID)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains)
				}
				assert.Nil(t, provider)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, provider)
			}
		})
	}
}

func TestRegisterStaticProvider(t *testing.T) {
	ctx := t.Context()
	const (
		issuer  = "https://example.com"
		jwksURI = "https://example.com/custom/jwks"
	)

	t.Run("register provider by issuer", func(t *testing.T) {
		provider, err := oidc.NewProvider(issuer, []string{"aud1"})
		assert.NoError(t, err)

		handler, err := NewOIDC(ctx)
		assert.NoError(t, err)

		handler.RegisterStaticProvider(provider)

		// Verify provider is stored by issuer
		storedProvider, ok := handler.staticProviders[issuer]
		assert.True(t, ok)
		assert.Equal(t, provider, storedProvider)
	})

	t.Run("register provider by custom jwks uri", func(t *testing.T) {
		provider, err := oidc.NewProvider(issuer, []string{"aud1"}, oidc.WithCustomJWKSURI(jwksURI))
		assert.NoError(t, err)

		handler, err := NewOIDC(ctx)
		assert.NoError(t, err)

		handler.RegisterStaticProvider(provider)

		// Verify provider is stored by custom JWKS URI, not by issuer
		_, okByIssuer := handler.staticProviders[issuer]
		assert.False(t, okByIssuer)

		storedProvider, okByJwksURI := handler.staticProviders[jwksURI]
		assert.True(t, okByJwksURI)
		assert.Equal(t, provider, storedProvider)
	})
}

func TestParseAndValidateEdgeCases(t *testing.T) {
	ctx := t.Context()
	// create a JWKS test server
	var (
		wkocResponse  []byte
		jwksResponse  []byte
		introspection []byte
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
		fmt.Fprintln(w, string(introspection))
	})

	httpsTestServer := httptest.NewTLSServer(mux)
	defer httpsTestServer.Close()

	// create an RSA key pair
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("could not generate RSA key: %s", err)
	}

	rsaPublicKey := &rsaPrivateKey.PublicKey
	rsaKeyID := uuid.Must(uuid.NewV4()).String()

	// create a x509 certificate
	cert := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"KMS, Inc"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(5 * time.Minute),
	}

	x509Cert, err := x509.CreateCertificate(rand.Reader, &cert, &cert, rsaPublicKey, rsaPrivateKey)
	if err != nil {
		t.Fatalf("could not create x509 certificate: %s", err)
	}

	// create the JWKS response
	eBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(eBytes, uint64(rsaPrivateKey.E))
	eBytes = bytes.TrimLeft(eBytes, "\x00")
	sum := sha256.Sum256(x509Cert)

	jwksResponse, err = json.Marshal(map[string]any{
		"keys": []map[string]any{{
			"kty":      "RSA",
			"x5t#S256": base64.RawURLEncoding.EncodeToString(sum[:]),
			"e":        base64.RawURLEncoding.EncodeToString(eBytes),
			"use":      "sig",
			"kid":      rsaKeyID,
			"x5c":      []string{base64.StdEncoding.EncodeToString(x509Cert)},
			"alg":      "RS256",
			"n":        base64.RawURLEncoding.EncodeToString(rsaPrivateKey.N.Bytes()),
		}},
	})
	if err != nil {
		t.Fatalf("could not marshal JWKS response: %s", err)
	}

	wkocResponse, err = json.Marshal(map[string]any{
		"issuer":                 httpsTestServer.URL,
		"jwks_uri":               httpsTestServer.URL + "/jwks",
		"introspection_endpoint": httpsTestServer.URL + "/oauth2/introspect",
	})
	if err != nil {
		t.Fatalf("could not marshal WKOC response: %s", err)
	}

	// create a provider that trusts the test server certificate
	certpool := x509.NewCertPool()
	certpool.AddCert(httpsTestServer.Certificate())
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: certpool}}}
	provider, err := oidc.NewProvider(httpsTestServer.URL, []string{"aud1"},
		oidc.WithPublicHTTPClient(cl),
		oidc.WithSecureHTTPClient(cl),
	)
	if err != nil {
		t.Fatalf("could not create https provider: %s", err)
	}

	t.Run("invalid token string", func(t *testing.T) {
		hdl, err := NewOIDC(ctx,
			WithIssuerClaimKeys(oidc.DefaultIssuerClaims...),
			WithStaticProvider(provider),
		)
		assert.NoError(t, err)

		err = hdl.ParseAndValidate(t.Context(), "not-a-valid-jwt", "", nil, false)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("missing issuer in claims", func(t *testing.T) {
		hdl, err := NewOIDC(ctx,
			WithIssuerClaimKeys("iss"),
			WithStaticProvider(provider),
		)
		assert.NoError(t, err)

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub": "me",
			"exp": time.Now().Add(48 * time.Hour).Unix(),
			"aud": []string{"aud1"},
		})
		token.Header["kid"] = rsaKeyID
		token.Header["jku"] = httpsTestServer.URL + "/jwks"

		tokenString, err := token.SignedString(rsaPrivateKey)
		assert.NoError(t, err)

		err = hdl.ParseAndValidate(t.Context(), tokenString, "", nil, false)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("missing kid in token header", func(t *testing.T) {
		hdl, err := NewOIDC(ctx,
			WithIssuerClaimKeys(oidc.DefaultIssuerClaims...),
			WithStaticProvider(provider),
		)
		assert.NoError(t, err)

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub": "me",
			"iss": httpsTestServer.URL,
			"exp": time.Now().Add(48 * time.Hour).Unix(),
			"aud": []string{"aud1"},
		})
		// Note: not setting kid header
		token.Header["jku"] = httpsTestServer.URL + "/jwks"

		tokenString, err := token.SignedString(rsaPrivateKey)
		assert.NoError(t, err)

		err = hdl.ParseAndValidate(t.Context(), tokenString, "", nil, false)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("http scheme rejected", func(t *testing.T) {
		hdl, err := NewOIDC(ctx,
			WithIssuerClaimKeys(oidc.DefaultIssuerClaims...),
			WithStaticProvider(provider),
		)
		assert.NoError(t, err)

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub": "me",
			"iss": "http://insecure.example.com",
			"exp": time.Now().Add(48 * time.Hour).Unix(),
			"aud": []string{"aud1"},
		})
		token.Header["kid"] = rsaKeyID

		tokenString, err := token.SignedString(rsaPrivateKey)
		assert.NoError(t, err)

		err = hdl.ParseAndValidate(t.Context(), tokenString, "", nil, false)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("use introspection cache", func(t *testing.T) {
		introspection = []byte(`{"active": true}`)
		hdl, err := NewOIDC(ctx,
			WithIssuerClaimKeys(oidc.DefaultIssuerClaims...),
			WithStaticProvider(provider),
		)
		assert.NoError(t, err)

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub": "me",
			"iss": httpsTestServer.URL,
			"exp": time.Now().Add(48 * time.Hour).Unix(),
			"aud": []string{"aud1"},
		})
		token.Header["kid"] = rsaKeyID
		token.Header["jku"] = httpsTestServer.URL + "/jwks"
		tokenString, err := token.SignedString(rsaPrivateKey)
		assert.NoError(t, err)

		claims := struct {
			Subject string `json:"sub"`
		}{}

		// First call - will call introspection endpoint
		err = hdl.ParseAndValidate(t.Context(), tokenString, "", &claims, true)
		assert.NoError(t, err)

		// Second call with cache enabled - should use cached introspection
		err = hdl.ParseAndValidate(t.Context(), tokenString, "", &claims, true)
		assert.NoError(t, err)
	})

	t.Run("signing key caching", func(t *testing.T) {
		introspection = []byte(`{"active": true}`)
		hdl, err := NewOIDC(ctx,
			WithIssuerClaimKeys(oidc.DefaultIssuerClaims...),
			WithStaticProvider(provider),
		)
		assert.NoError(t, err)

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub": "me",
			"iss": httpsTestServer.URL,
			"exp": time.Now().Add(48 * time.Hour).Unix(),
			"aud": []string{"aud1"},
		})
		token.Header["kid"] = rsaKeyID
		token.Header["jku"] = httpsTestServer.URL + "/jwks"
		tokenString, err := token.SignedString(rsaPrivateKey)
		assert.NoError(t, err)

		claims := struct {
			Subject string `json:"sub"`
		}{}

		// First call - will fetch signing key from JWKS endpoint
		err = hdl.ParseAndValidate(t.Context(), tokenString, "", &claims, false)
		assert.NoError(t, err)

		// Second call - should use cached signing key
		err = hdl.ParseAndValidate(t.Context(), tokenString, "", &claims, false)
		assert.NoError(t, err)
	})

	t.Run("token without jku falls back to issuer", func(t *testing.T) {
		introspection = []byte(`{"active": true}`)
		hdl, err := NewOIDC(ctx,
			WithIssuerClaimKeys(oidc.DefaultIssuerClaims...),
			WithStaticProvider(provider),
		)
		assert.NoError(t, err)

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub": "me",
			"iss": httpsTestServer.URL,
			"exp": time.Now().Add(48 * time.Hour).Unix(),
			"aud": []string{"aud1"},
		})
		token.Header["kid"] = rsaKeyID
		// Note: not setting jku header, should fall back to using issuer for URL validation
		tokenString, err := token.SignedString(rsaPrivateKey)
		assert.NoError(t, err)

		claims := struct {
			Subject string `json:"sub"`
		}{}

		err = hdl.ParseAndValidate(t.Context(), tokenString, "", &claims, false)
		assert.NoError(t, err)
	})

	t.Run("invalid claims deserialization returns error", func(t *testing.T) {
		introspection = []byte(`{"active": true}`)
		hdl, err := NewOIDC(ctx,
			WithIssuerClaimKeys(oidc.DefaultIssuerClaims...),
			WithStaticProvider(provider),
		)
		assert.NoError(t, err)

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub": 12345, // sub should be a string, this will cause issues
			"iss": httpsTestServer.URL,
			"exp": time.Now().Add(48 * time.Hour).Unix(),
			"aud": []string{"aud1"},
		})
		token.Header["kid"] = rsaKeyID
		token.Header["jku"] = httpsTestServer.URL + "/jwks"
		tokenString, err := token.SignedString(rsaPrivateKey)
		assert.NoError(t, err)

		// Use a struct that expects sub to be a string
		claims := struct {
			Subject string `json:"sub"`
		}{}

		err = hdl.ParseAndValidate(t.Context(), tokenString, "", &claims, false)
		// This should fail because sub is a number but the struct expects a string
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidToken)
	})

	t.Run("no provider for issuer", func(t *testing.T) {
		hdl, err := NewOIDC(ctx,
			WithIssuerClaimKeys(oidc.DefaultIssuerClaims...),
		)
		assert.NoError(t, err)

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub": "me",
			"iss": "https://unknown-issuer.com",
			"exp": time.Now().Add(48 * time.Hour).Unix(),
			"aud": []string{"aud1"},
		})
		token.Header["kid"] = rsaKeyID
		tokenString, err := token.SignedString(rsaPrivateKey)
		assert.NoError(t, err)

		err = hdl.ParseAndValidate(t.Context(), tokenString, "", nil, false)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrNoProvider)
	})
}

func TestWithSessionManager(t *testing.T) {
	ctx := t.Context()
	t.Run("set session manager", func(t *testing.T) {
		hdl, err := NewOIDC(ctx, WithSessionManager(nil))
		assert.NoError(t, err)
		assert.Nil(t, hdl.sessionManager)
	})
}

func TestWithFeatureGates(t *testing.T) {
	ctx := t.Context()
	t.Run("set feature gates", func(t *testing.T) {
		fg := &commoncfg.FeatureGates{}
		hdl, err := NewOIDC(ctx, WithFeatureGates(fg))
		assert.NoError(t, err)
		assert.Equal(t, fg, hdl.featureGates)
	})
}

func TestParseAndValidateNoIntrospectionEndpoint(t *testing.T) {
	ctx := t.Context()
	// Create a test server without introspection endpoint
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

	httpsTestServer := httptest.NewTLSServer(mux)
	defer httpsTestServer.Close()

	// create an RSA key pair
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("could not generate RSA key: %s", err)
	}

	rsaPublicKey := &rsaPrivateKey.PublicKey
	rsaKeyID := uuid.Must(uuid.NewV4()).String()

	// create a x509 certificate
	cert := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"KMS, Inc"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(5 * time.Minute),
	}

	x509Cert, err := x509.CreateCertificate(rand.Reader, &cert, &cert, rsaPublicKey, rsaPrivateKey)
	if err != nil {
		t.Fatalf("could not create x509 certificate: %s", err)
	}

	// create the JWKS response
	eBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(eBytes, uint64(rsaPrivateKey.E))
	eBytes = bytes.TrimLeft(eBytes, "\x00")
	sum := sha256.Sum256(x509Cert)

	jwksResponse, err = json.Marshal(map[string]any{
		"keys": []map[string]any{{
			"kty":      "RSA",
			"x5t#S256": base64.RawURLEncoding.EncodeToString(sum[:]),
			"e":        base64.RawURLEncoding.EncodeToString(eBytes),
			"use":      "sig",
			"kid":      rsaKeyID,
			"x5c":      []string{base64.StdEncoding.EncodeToString(x509Cert)},
			"alg":      "RS256",
			"n":        base64.RawURLEncoding.EncodeToString(rsaPrivateKey.N.Bytes()),
		}},
	})
	if err != nil {
		t.Fatalf("could not marshal JWKS response: %s", err)
	}

	// WKOC response WITHOUT introspection_endpoint
	wkocResponse, err = json.Marshal(map[string]any{
		"issuer":   httpsTestServer.URL,
		"jwks_uri": httpsTestServer.URL + "/jwks",
		// Note: no introspection_endpoint field - this triggers ErrNoIntrospectionEndpoint
	})
	if err != nil {
		t.Fatalf("could not marshal WKOC response: %s", err)
	}

	// create a provider that trusts the test server certificate
	certpool := x509.NewCertPool()
	certpool.AddCert(httpsTestServer.Certificate())
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: certpool}}}
	provider, err := oidc.NewProvider(httpsTestServer.URL, []string{"aud1"},
		oidc.WithPublicHTTPClient(cl),
		oidc.WithSecureHTTPClient(cl),
	)
	if err != nil {
		t.Fatalf("could not create https provider: %s", err)
	}

	t.Run("token valid when no introspection endpoint configured", func(t *testing.T) {
		hdl, err := NewOIDC(ctx,
			WithIssuerClaimKeys(oidc.DefaultIssuerClaims...),
			WithStaticProvider(provider),
		)
		assert.NoError(t, err)

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub": "me",
			"iss": httpsTestServer.URL,
			"exp": time.Now().Add(48 * time.Hour).Unix(),
			"aud": []string{"aud1"},
		})
		token.Header["kid"] = rsaKeyID
		token.Header["jku"] = httpsTestServer.URL + "/jwks"
		tokenString, err := token.SignedString(rsaPrivateKey)
		assert.NoError(t, err)

		claims := struct {
			Subject string `json:"sub"`
		}{}

		// This should succeed - when there's no introspection endpoint,
		// the token is assumed to be active
		err = hdl.ParseAndValidate(t.Context(), tokenString, "", &claims, false)
		assert.NoError(t, err)
	})
}

func TestParseAndValidateTokenIntrospectionDisabled(t *testing.T) {
	ctx := t.Context()
	// Create a test server with introspection endpoint, but provider has introspection disabled
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
		// This should never be called because introspection is disabled
		t.Error("introspection endpoint should not be called when token introspection is disabled")
		w.WriteHeader(http.StatusForbidden)
	})

	httpsTestServer := httptest.NewTLSServer(mux)
	defer httpsTestServer.Close()

	// create an RSA key pair
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("could not generate RSA key: %s", err)
	}

	rsaPublicKey := &rsaPrivateKey.PublicKey
	rsaKeyID := uuid.Must(uuid.NewV4()).String()

	// create a x509 certificate
	cert := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"KMS, Inc"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(5 * time.Minute),
	}

	x509Cert, err := x509.CreateCertificate(rand.Reader, &cert, &cert, rsaPublicKey, rsaPrivateKey)
	if err != nil {
		t.Fatalf("could not create x509 certificate: %s", err)
	}

	// create the JWKS response
	eBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(eBytes, uint64(rsaPrivateKey.E))
	eBytes = bytes.TrimLeft(eBytes, "\x00")
	sum := sha256.Sum256(x509Cert)

	jwksResponse, err = json.Marshal(map[string]any{
		"keys": []map[string]any{{
			"kty":      "RSA",
			"x5t#S256": base64.RawURLEncoding.EncodeToString(sum[:]),
			"e":        base64.RawURLEncoding.EncodeToString(eBytes),
			"use":      "sig",
			"kid":      rsaKeyID,
			"x5c":      []string{base64.StdEncoding.EncodeToString(x509Cert)},
			"alg":      "RS256",
			"n":        base64.RawURLEncoding.EncodeToString(rsaPrivateKey.N.Bytes()),
		}},
	})
	if err != nil {
		t.Fatalf("could not marshal JWKS response: %s", err)
	}

	// WKOC response WITH introspection_endpoint (but provider will have it disabled)
	wkocResponse, err = json.Marshal(map[string]any{
		"issuer":                 httpsTestServer.URL,
		"jwks_uri":               httpsTestServer.URL + "/jwks",
		"introspection_endpoint": httpsTestServer.URL + "/oauth2/introspect",
	})
	if err != nil {
		t.Fatalf("could not marshal WKOC response: %s", err)
	}

	// create a provider that trusts the test server certificate, with introspection disabled
	certpool := x509.NewCertPool()
	certpool.AddCert(httpsTestServer.Certificate())
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: certpool}}}
	provider, err := oidc.NewProvider(httpsTestServer.URL, []string{"aud1"},
		oidc.WithPublicHTTPClient(cl),
		oidc.WithSecureHTTPClient(cl),
		oidc.WithDisableTokenIntrospection(true),
	)
	if err != nil {
		t.Fatalf("could not create https provider: %s", err)
	}

	t.Run("token valid when token introspection is disabled", func(t *testing.T) {
		hdl, err := NewOIDC(ctx,
			WithIssuerClaimKeys(oidc.DefaultIssuerClaims...),
			WithStaticProvider(provider),
		)
		assert.NoError(t, err)

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub": "me",
			"iss": httpsTestServer.URL,
			"exp": time.Now().Add(48 * time.Hour).Unix(),
			"aud": []string{"aud1"},
		})
		token.Header["kid"] = rsaKeyID
		token.Header["jku"] = httpsTestServer.URL + "/jwks"
		tokenString, err := token.SignedString(rsaPrivateKey)
		assert.NoError(t, err)

		claims := struct {
			Subject string `json:"sub"`
		}{}

		// This should succeed - when token introspection is disabled,
		// the token is assumed to be active
		err = hdl.ParseAndValidate(t.Context(), tokenString, "", &claims, false)
		assert.NoError(t, err)
	})
}

func TestParseAndValidateIntrospectionError(t *testing.T) {
	ctx := t.Context()
	// Create a test server with an introspection endpoint that returns an error
	var (
		wkocResponse            []byte
		jwksResponse            []byte
		introspectionStatusCode int
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
		w.WriteHeader(introspectionStatusCode)
		fmt.Fprintln(w, `{"error": "server_error"}`)
	})

	httpsTestServer := httptest.NewTLSServer(mux)
	defer httpsTestServer.Close()

	// create an RSA key pair
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("could not generate RSA key: %s", err)
	}

	rsaPublicKey := &rsaPrivateKey.PublicKey
	rsaKeyID := uuid.Must(uuid.NewV4()).String()

	// create a x509 certificate
	cert := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"KMS, Inc"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(5 * time.Minute),
	}

	x509Cert, err := x509.CreateCertificate(rand.Reader, &cert, &cert, rsaPublicKey, rsaPrivateKey)
	if err != nil {
		t.Fatalf("could not create x509 certificate: %s", err)
	}

	// create the JWKS response
	eBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(eBytes, uint64(rsaPrivateKey.E))
	eBytes = bytes.TrimLeft(eBytes, "\x00")
	sum := sha256.Sum256(x509Cert)

	jwksResponse, err = json.Marshal(map[string]any{
		"keys": []map[string]any{{
			"kty":      "RSA",
			"x5t#S256": base64.RawURLEncoding.EncodeToString(sum[:]),
			"e":        base64.RawURLEncoding.EncodeToString(eBytes),
			"use":      "sig",
			"kid":      rsaKeyID,
			"x5c":      []string{base64.StdEncoding.EncodeToString(x509Cert)},
			"alg":      "RS256",
			"n":        base64.RawURLEncoding.EncodeToString(rsaPrivateKey.N.Bytes()),
		}},
	})
	if err != nil {
		t.Fatalf("could not marshal JWKS response: %s", err)
	}

	wkocResponse, err = json.Marshal(map[string]any{
		"issuer":                 httpsTestServer.URL,
		"jwks_uri":               httpsTestServer.URL + "/jwks",
		"introspection_endpoint": httpsTestServer.URL + "/oauth2/introspect",
	})
	if err != nil {
		t.Fatalf("could not marshal WKOC response: %s", err)
	}

	// create a provider that trusts the test server certificate
	certpool := x509.NewCertPool()
	certpool.AddCert(httpsTestServer.Certificate())
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: certpool}}}
	provider, err := oidc.NewProvider(httpsTestServer.URL, []string{"aud1"},
		oidc.WithPublicHTTPClient(cl),
		oidc.WithSecureHTTPClient(cl),
	)
	if err != nil {
		t.Fatalf("could not create https provider: %s", err)
	}

	t.Run("introspection server error", func(t *testing.T) {
		introspectionStatusCode = http.StatusInternalServerError

		hdl, err := NewOIDC(ctx,
			WithIssuerClaimKeys(oidc.DefaultIssuerClaims...),
			WithStaticProvider(provider),
		)
		assert.NoError(t, err)

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub": "me",
			"iss": httpsTestServer.URL,
			"exp": time.Now().Add(48 * time.Hour).Unix(),
			"aud": []string{"aud1"},
		})
		token.Header["kid"] = rsaKeyID
		token.Header["jku"] = httpsTestServer.URL + "/jwks"
		tokenString, err := token.SignedString(rsaPrivateKey)
		assert.NoError(t, err)

		claims := struct {
			Subject string `json:"sub"`
		}{}

		// This should fail because introspection returns an error
		err = hdl.ParseAndValidate(t.Context(), tokenString, "", &claims, false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "introspecting token")
	})
}
