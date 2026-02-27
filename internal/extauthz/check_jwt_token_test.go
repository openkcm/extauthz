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

			hdl, err := handler.NewOIDC(handler.WithStaticProvider(p))
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
			result := srv.checkJWTToken(t.Context(), tc.bearerToken, "GET", "our.service.com", "/foo/bar")

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
