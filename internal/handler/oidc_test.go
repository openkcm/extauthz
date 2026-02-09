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

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/openkcm/common-sdk/pkg/oidc"
	"github.com/stretchr/testify/assert"
)

func TestNewOIDC(t *testing.T) {
	t.Run("no panic with nil options", func(t *testing.T) {
		assert.NotPanics(t, func() {
			//nolint:errcheck
			NewOIDC(nil)
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
			name: "with cache expiration",
			opts: []OIDCOption{
				WithProviderCacheExpiration(30*time.Second, 10*time.Minute),
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
			hdl, err := NewOIDC(tc.opts...)
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
	rsaKeyID := uuid.New().String()

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
			hdl, err := NewOIDC(handlerOpts...)
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
