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
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/extauthz/internal/testutils"
)

func TestNewProvider(t *testing.T) {
	issuerURL, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatalf("failed to parse URL: %s", err)
	}
	customJWKSURI, err := url.Parse("https://example.com/jwks")
	if err != nil {
		t.Fatalf("failed to parse URL: %s", err)
	}

	// create the test cases
	tests := []struct {
		name      string
		issuerURL *url.URL
		audiences []string
		opts      []ProviderOption
		wantError bool
	}{
		{
			name: "zero values",
		}, {
			name:      "without cache",
			issuerURL: issuerURL,
			audiences: []string{"aud1", "aud2"},
			opts: []ProviderOption{
				WithoutCache(),
			},
			wantError: false,
		}, {
			name:      "with signing key cache expiration",
			issuerURL: issuerURL,
			audiences: []string{"aud1", "aud2"},
			opts: []ProviderOption{
				WithSigningKeyCacheExpiration(30*time.Second, 10*time.Minute),
			},
		}, {
			name:      "with nil client",
			issuerURL: issuerURL,
			audiences: []string{"aud1", "aud2"},
			opts: []ProviderOption{
				WithClient(nil),
			},
			wantError: true,
		}, {
			name:      "with client",
			issuerURL: issuerURL,
			audiences: []string{"aud1", "aud2"},
			opts: []ProviderOption{
				WithClient(http.DefaultClient),
			},
		}, {
			name:      "with nil JWKS URI",
			issuerURL: issuerURL,
			audiences: []string{"aud1", "aud2"},
			opts: []ProviderOption{
				WithCustomJWKSURI(nil),
			},
			wantError: true,
		}, {
			name:      "with custom JWKS URI",
			issuerURL: issuerURL,
			audiences: []string{"aud1", "aud2"},
			opts: []ProviderOption{
				WithCustomJWKSURI(customJWKSURI),
			},
		},
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange

			// Act
			p, err := NewProvider(tc.issuerURL, tc.audiences, tc.opts...)

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

type jwksKeys struct {
	Keys []jwksKey `json:"keys"`
}

type jwksKey struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5t string   `json:"x5t#S256"`
	X5c []string `json:"x5c"`
	Alg string   `json:"alg"`
}

func TestSigningKeyFor(t *testing.T) {
	// Use a sync.Map to store the responses for the httptest server
	// so we can change the responses for each test case without
	// running into data races.
	var responses sync.Map

	// create a JWKS test server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		value, _ := responses.Load("wkoc")

		fmt.Fprintln(w, value)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		value, _ := responses.Load("jwks")

		fmt.Fprintln(w, value)
	})
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()
	responses.Store("wkoc", `{"jwks_uri": "`+ts.URL+`/jwks"}`)
	providerURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("could not parse issuer URL: %s", err)
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

	// create the JWKS response using the mutator to be able to change
	// it for each test case
	eBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(eBytes, uint64(rsaPrivateKey.E))
	eBytes = bytes.TrimLeft(eBytes, "\x00")
	sum := sha256.Sum256(x509Cert)
	mutator := testutils.NewMutator(func() jwksKey {
		return jwksKey{
			Kty: "RSA",
			Kid: rsaKeyID,
			Use: "sig",
			N:   base64.RawURLEncoding.EncodeToString(rsaPrivateKey.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(eBytes),
			X5t: base64.RawURLEncoding.EncodeToString(sum[:]),
			X5c: []string{base64.StdEncoding.EncodeToString(x509Cert)},
			Alg: "RS256",
		}
	})

	// create the test cases
	tests := []struct {
		name      string
		jwksKey   jwksKey
		keyID     string
		wantError bool
	}{
		{
			name:      "zero values",
			jwksKey:   mutator(func(k *jwksKey) {}),
			wantError: true,
		}, {
			name:      "invalid key ID",
			jwksKey:   mutator(func(k *jwksKey) {}),
			keyID:     uuid.New().String(),
			wantError: true,
		}, {
			name:      "valid key ID",
			jwksKey:   mutator(func(k *jwksKey) {}),
			keyID:     rsaKeyID,
			wantError: false,
		}, {
			name: "JWKS response invalid use",
			jwksKey: mutator(func(k *jwksKey) {
				k.Use = "enc"
			}),
			keyID:     rsaKeyID,
			wantError: true,
		},
	}

	// create a provider, which trusts the http test server certificate
	certpool := x509.NewCertPool()
	certpool.AddCert(ts.Certificate())
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: certpool}}}
	p, err := NewProvider(providerURL, []string{"aud1"},
		WithClient(cl),
		WithoutCache(),
	)
	if err != nil {
		t.Fatalf("could not create provider: %s", err)
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			jwksResponse, err := json.Marshal(
				jwksKeys{Keys: []jwksKey{tc.jwksKey}},
			)
			if err != nil {
				t.Fatalf("could not marshal JWKS response: %s", err)
			}
			responses.Store("jwks", string(jwksResponse))

			// Act
			key, err := p.SigningKeyFor(t.Context(), tc.keyID)

			// Assert
			if tc.wantError {
				if err == nil {
					t.Error("expected error, but got nil")
				}
				if key != nil {
					t.Errorf("expected nil key, but got: %v", key)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %s", err)
				}
			}
		})
	}
}

// localRoundTripper is an http.RoundTripper that executes HTTP transactions by
// using handler directly, instead of going over an HTTP connection.
type localRoundTripper struct {
	handler http.Handler
}

func (l localRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	l.handler.ServeHTTP(w, req)
	return w.Result(), nil
}

func TestProvider_introspect(t *testing.T) {
	issuerURL, err := url.Parse("https://example.com")
	require.NoError(t, err)
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":  "me",
		"mail": "me@my.world",
		"iss":  issuerURL.String(),
		"exp":  time.Now().Add(48 * time.Hour).Unix(),
	})
	rawToken, err := token.SignedString(priv)
	require.NoError(t, err)

	tests := []struct {
		name      string
		issuerURL *url.URL
		audiences []string
		opts      []ProviderOption
		rawToken  string
		active    bool
		want      introspection
		wantErr   assert.ErrorAssertionFunc
	}{
		{
			name:      "Introspect active token",
			issuerURL: issuerURL,
			audiences: []string{"aud1", "aud2"},
			opts:      []ProviderOption{WithSigningKeyCacheExpiration(30*time.Second, 10*time.Minute)},
			active:    true,
			rawToken:  rawToken,
			want: introspection{
				Active: true,
			},
			wantErr: assert.NoError,
		},
		{
			name:      "Introspect inactive token",
			issuerURL: issuerURL,
			audiences: []string{"aud1", "aud2"},
			opts:      []ProviderOption{WithSigningKeyCacheExpiration(30*time.Second, 10*time.Minute)},
			active:    false,
			rawToken:  rawToken,
			want: introspection{
				Active: false,
			},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.opts = append(tt.opts, WithClient(&http.Client{
				Transport: localRoundTripper{
					http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if err := json.NewEncoder(w).Encode(introspection{Active: tt.active}); err != nil {
							w.WriteHeader(http.StatusInternalServerError)
						}
					}),
				},
			}))

			if err != nil {
				t.Fatalf("failed to parse URL: %s", err)
			}
			provider, err := NewProvider(tt.issuerURL, tt.audiences, tt.opts...)
			require.NoError(t, err)

			got, err := provider.introspect(t.Context(), tt.rawToken)
			if !tt.wantErr(t, err, fmt.Sprintf("introspect(ctx, %v)", tt.rawToken)) {
				return
			}
			assert.Equalf(t, tt.want, got, "introspect(ctx, %v)", tt.rawToken)
		})
	}
}
