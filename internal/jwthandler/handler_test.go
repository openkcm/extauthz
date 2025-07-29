package jwthandler

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
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"k8s.io/client-go/rest/fake"
)

func TestNewHandler(t *testing.T) {
	providerUrl, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatalf("failed to parse URL: %s", err)
	}

	// create the test cases
	tests := []struct {
		name      string
		opts      []HandlerOption
		checkFunc func(*Handler) error
		wantError bool
	}{
		{
			name: "zero values",
		}, {
			name: "with cache expiration",
			opts: []HandlerOption{
				WithProviderCacheExpiration(30*time.Second, 10*time.Minute),
			},
		}, {
			name: "with issuer claim keys iss",
			opts: []HandlerOption{
				WithIssuerClaimKeys(DefaultIssuerClaims...),
			},
			checkFunc: issuerClaimHandler("iss"),
		}, {
			name: "with issuer claim keys ias_iss",
			opts: []HandlerOption{
				WithIssuerClaimKeys("ias_iss"),
			},
			checkFunc: issuerClaimHandler("ias_iss"),
		}, {
			name: "with nil provider",
			opts: []HandlerOption{
				WithProvider(nil),
			},
			wantError: true,
		}, {
			name: "with provider",
			opts: []HandlerOption{
				WithProvider(&Provider{
					issuerURL: providerUrl,
				}),
			},
			checkFunc: func(h *Handler) error {
				if _, found := h.cache.Get(providerUrl.Host); !found {
					return errors.New("expected providers to be initialized")
				}
				return nil
			},
		}, {
			name: "with k8s providers",
			opts: []HandlerOption{
				WithK8sJWTProviders(true, "crdAPIGroup", "crdAPIVersion", "crdName", "crdNameSpace"),
			},
			checkFunc: func(h *Handler) error {
				if !h.k8sJWTProvidersEnabled {
					return errors.New("expected k8s providers to be enabled")
				}
				return nil
			},
		},
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange

			// Act
			hdl, err := NewHandler(tc.opts...)
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
	var jwksResponse []byte
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		fmt.Fprintln(w, string(jwksResponse))
	})

	mux.HandleFunc("/oauth2/introspect/fail", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(introspection{Active: false}); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("/oauth2/introspect/success", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(introspection{Active: true}); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("/oauth2/introspect", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(introspection{Active: true}); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	})

	ts := httptest.NewTLSServer(mux)
	defer ts.Close()
	providerURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("could not parse issuer URL: %s", err)
	}
	jwksURI, err := url.Parse(ts.URL + "/jwks")
	if err != nil {
		t.Fatalf("could not parse JWKS URI: %s", err)
	}

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

	// create the test cases
	tests := []struct {
		name            string
		issuerClaimKeys []string
		token           *jwt.Token
		providerOptions []ProviderOption
		wantError       bool
	}{
		{
			name:            "zero values",
			issuerClaimKeys: DefaultIssuerClaims,
			wantError:       true,
		}, {
			name:            "invalid token: wrong IAS issuer",
			issuerClaimKeys: []string{"ias_iss"},
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
			issuerClaimKeys: DefaultIssuerClaims,
			token: jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub":  "me",
				"mail": "me@my.world",
				"iss":  "https://invalid.issuer",
				"exp":  time.Now().Add(48 * time.Hour).Unix(),
				"aud":  []string{"aud1"},
			}),
			wantError: true,
		}, {
			name:            "invalid token: no audience",
			issuerClaimKeys: DefaultIssuerClaims,
			token: jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub":  "me",
				"mail": "me@my.world",
				"iss":  providerURL.String(),
				"exp":  time.Now().Add(48 * time.Hour).Unix(),
			}),
			wantError: true,
		}, {
			name:            "invalid token: wrong audience",
			issuerClaimKeys: DefaultIssuerClaims,
			token: jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub":  "me",
				"mail": "me@my.world",
				"iss":  providerURL.String(),
				"exp":  time.Now().Add(48 * time.Hour).Unix(),
				"aud":  []string{"vip"},
			}),
			wantError: true,
		}, {
			name:            "invalid token: not before",
			issuerClaimKeys: DefaultIssuerClaims,
			token: jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub":  "me",
				"mail": "me@my.world",
				"iss":  providerURL.String(),
				"nbf":  time.Now().Add(24 * time.Hour).Unix(),
				"exp":  time.Now().Add(48 * time.Hour).Unix(),
				"aud":  []string{"aud1", "aud2"},
			}),
			wantError: true,
		}, {
			name:            "invalid token: expired",
			issuerClaimKeys: DefaultIssuerClaims,
			token: jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub":  "me",
				"mail": "me@my.world",
				"iss":  providerURL.String(),
				"exp":  time.Now().Add(-48 * time.Hour).Unix(),
				"aud":  []string{"aud1", "aud2"},
			}),
			wantError: true,
		}, {
			name:            "invalid token: no expiry",
			issuerClaimKeys: DefaultIssuerClaims,
			token: jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub":  "me",
				"mail": "me@my.world",
				"iss":  providerURL.String(),
				"aud":  []string{"aud1", "aud2"},
			}),
			wantError: true,
		}, {
			name:            "valid token",
			issuerClaimKeys: DefaultIssuerClaims,
			token: jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub":  "me",
				"mail": "me@my.world",
				"iss":  providerURL.String(),
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
				"ias_iss": providerURL.String(),
				"exp":     time.Now().Add(48 * time.Hour).Unix(),
				"aud":     []string{"aud1", "aud2"},
			}),
			wantError: false,
		}, {
			name:            "valid IAS token with iss",
			issuerClaimKeys: DefaultIssuerClaims,
			token: jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub":  "me",
				"mail": "me@my.world",
				"iss":  providerURL.String(),
				"exp":  time.Now().Add(48 * time.Hour).Unix(),
				"aud":  []string{"aud1", "aud2"},
			}),
			wantError: false,
		}, {
			name:            "revoked token",
			issuerClaimKeys: DefaultIssuerClaims,
			token: jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub":  "me",
				"mail": "me@my.world",
				"iss":  providerURL.String(),
				"exp":  time.Now().Add(48 * time.Hour).Unix(),
				"aud":  []string{"aud1", "aud2"},
			}),
			providerOptions: []ProviderOption{
				WithIntrospectTokenURL(providerURL.JoinPath("oauth2", "introspect", "fail")),
			},
			wantError: true,
		}, {
			name:            "Active token",
			issuerClaimKeys: DefaultIssuerClaims,
			token: jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub":  "me",
				"mail": "me@my.world",
				"iss":  providerURL.String(),
				"exp":  time.Now().Add(48 * time.Hour).Unix(),
				"aud":  []string{"aud1", "aud2"},
			}),
			providerOptions: []ProviderOption{
				WithIntrospectTokenURL(providerURL.JoinPath("oauth2", "introspect", "success")),
			},
			wantError: false,
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
			opts := append([]ProviderOption{
				WithClient(cl),
				WithCustomJWKSURI(jwksURI),
			}, tc.providerOptions...)
			p, err := NewProvider(providerURL, []string{"aud1"}, opts...)
			if err != nil {
				t.Fatalf("could not create provider: %s", err)
			}
			hdl, err := NewHandler(
				WithIssuerClaimKeys(tc.issuerClaimKeys...),
				WithProvider(p),
			)
			if err != nil {
				t.Fatalf("could not create handler: %s", err)
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
				token.Header["jku"] = jwksURI.String()
				tokenString, err = token.SignedString(rsaPrivateKey)
				if err != nil {
					t.Fatalf("could not sign token: %s", err)
				}
			}

			// Act
			err = hdl.ParseAndValidate(t.Context(), tokenString, &claims, false)

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

func issuerClaimHandler(claimKey string) func(h *Handler) error {
	return func(h *Handler) error {
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

func TestK8sJWTProviderFor(t *testing.T) {
	// create the test cases
	tests := []struct {
		name            string
		issuer          string
		invalidResponse []byte
		response        JWTProviderResult
		error           error
		wantError       bool
	}{
		{
			name:      "zero values",
			wantError: true,
		}, {
			name:      "mock error",
			error:     errors.New("mock error"),
			wantError: true,
		}, {
			name:            "invalid response",
			invalidResponse: []byte("invalid response"),
			wantError:       true,
		}, {
			name:   "no providers",
			issuer: "foo",
			response: JWTProviderResult{
				Items: []JWTProvider{},
			},
			wantError: true,
		}, {
			name:   "found providers without the issuer",
			issuer: "example.com",
			response: JWTProviderResult{
				Items: []JWTProvider{
					{
						Spec: Spec{
							Issuer:     "https://foo.com/",
							RemoteJwks: RemoteJWKS{URI: "https://foo.com/jwks"},
							Audiences:  []string{"aud1", "aud2"},
						},
					}, {
						Spec: Spec{
							Issuer:     "https://bar.com/",
							RemoteJwks: RemoteJWKS{URI: "https://bar.com/jwk"},
							Audiences:  []string{"aud1", "aud2"},
						},
					},
				},
			},
			wantError: true,
		}, {
			name:   "found providers without the issuer",
			issuer: "example.com",
			response: JWTProviderResult{
				Items: []JWTProvider{
					{
						Spec: Spec{
							Issuer:     "https://foo.com/",
							RemoteJwks: RemoteJWKS{URI: "https://foo.com/jwks"},
							Audiences:  []string{"aud1", "aud2"},
						},
					}, {
						Spec: Spec{
							Issuer:     "%https://bar.com/",
							RemoteJwks: RemoteJWKS{URI: "%https://bar.com/jwks"},
							Audiences:  []string{"aud1", "aud2"},
						},
					},
				},
			},
			wantError: true,
		}, {
			name:   "found providers including the issuer with invalid JWKS URI",
			issuer: "example.com",
			response: JWTProviderResult{
				Items: []JWTProvider{
					{
						Spec: Spec{
							Issuer:     "https://example.com/",
							RemoteJwks: RemoteJWKS{URI: "%https://example.com/jwks"},
							Audiences:  []string{"aud1", "aud2"},
						},
					}, {
						Spec: Spec{
							Issuer:     "%https://bar.com/",
							RemoteJwks: RemoteJWKS{URI: "%https://bar.com/jwks"},
							Audiences:  []string{"aud1", "aud2"},
						},
					},
				},
			},
			wantError: true,
		}, {
			name:   "found providers including the issuer",
			issuer: "example.com",
			response: JWTProviderResult{
				Items: []JWTProvider{
					{
						Spec: Spec{
							Issuer:     "https://example.com/",
							RemoteJwks: RemoteJWKS{URI: "https://example.com/jwks"},
							Audiences:  []string{"aud1", "aud2"},
						},
					}, {
						Spec: Spec{
							Issuer:     "%https://bar.com/",
							RemoteJwks: RemoteJWKS{URI: "%https://bar.com/jwks"},
							Audiences:  []string{"aud1", "aud2"},
						},
					},
				},
			},
			wantError: false,
		},
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			hdl, err := NewHandler(WithK8sJWTProviders(true, "crdAPIGroup", "crdAPIVersion", "crdName", "crdNameSpace"))
			if err != nil {
				t.Fatalf("could not create handler: %s", err)
			}
			fakeResponse, err := json.Marshal(tc.response)
			if err != nil {
				t.Fatalf("could not marshal fake response: %s", err)
			}
			if tc.invalidResponse != nil {
				fakeResponse = tc.invalidResponse
			}
			fakeK8sRestClient := &fake.RESTClient{
				Err: tc.error,
				Resp: &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewReader(fakeResponse)),
				},
			}

			// Act
			p, err := hdl.k8sJWTProviderFor(fakeK8sRestClient, tc.issuer)

			// Assert
			if tc.wantError {
				if err == nil {
					t.Error("expected error, but got nil")
				}
				if p != nil {
					t.Errorf("expected nil provider, but got: %v", p)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %s", err)
				}
			}
		})
	}
}
