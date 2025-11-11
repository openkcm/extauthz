package oidc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
)

type handlerTestSuite struct {
	suite.Suite

	jwks          *jwksHandler
	ts            *httptest.Server
	rsaPrivateKey *rsa.PrivateKey
	hdl           *Handler
	token         *jwt.Token
	provider      *Provider
}

func TestHandlerSuite(t *testing.T) {
	suite.Run(t, new(handlerTestSuite))
}

func (s *handlerTestSuite) SetupSuite() {
	var err error

	// create an RSA key pair
	s.rsaPrivateKey, err = rsa.GenerateKey(rand.Reader, 4096)
	s.Require().NoError(err)

	s.jwks = newJWKSHandler()
	s.ts = httptest.NewTLSServer(s.jwks)

	providerURL, err := url.Parse(s.ts.URL)
	s.Require().NoError(err)

	jwksURI, err := url.Parse(s.ts.URL + "/jwks")
	s.Require().NoError(err)

	introspectionURL, err := url.Parse(s.ts.URL + "/oauth2/introspect")
	s.Require().NoError(err)

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
	x509Cert, err := x509.CreateCertificate(rand.Reader, &cert, &cert, &s.rsaPrivateKey.PublicKey, s.rsaPrivateKey)
	s.Require().NoError(err)

	// create the JWKS response
	eBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(eBytes, uint64(s.rsaPrivateKey.E))
	eBytes = bytes.TrimLeft(eBytes, "\x00")
	sum := sha256.Sum256(x509Cert)
	s.jwks.jwksResponse, err = json.Marshal(map[string]any{
		"keys": []map[string]any{{
			"kty":      "RSA",
			"x5t#S256": base64.RawURLEncoding.EncodeToString(sum[:]),
			"e":        base64.RawURLEncoding.EncodeToString(eBytes),
			"use":      "sig",
			"kid":      rsaKeyID,
			"x5c":      []string{base64.StdEncoding.EncodeToString(x509Cert)},
			"alg":      "RS256",
			"n":        base64.RawURLEncoding.EncodeToString(s.rsaPrivateKey.N.Bytes()),
		}},
	})
	s.Require().NoError(err)

	certpool := x509.NewCertPool()
	certpool.AddCert(s.ts.Certificate())
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: certpool}}}
	s.provider, err = NewProvider(providerURL, []string{"aud1"},
		WithClient(cl),
		WithJWKSURI(jwksURI),
		WithIntrospectTokenURL(introspectionURL),
	)
	s.Require().NoError(err)
	s.hdl, err = NewHandler(WithIssuerClaimKeys(DefaultIssuerClaims...), WithStaticProvider(s.provider))
	s.Require().NoError(err)

	s.token = jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":  "me",
		"mail": "me@my.world",
		"iss":  providerURL.String(),
		"exp":  time.Now().Add(48 * time.Hour).Unix(),
		"aud":  []string{"aud1", "aud2"},
	})
	s.token.Header["kid"] = rsaKeyID
	s.token.Header["jku"] = jwksURI.String()
}

func (s *handlerTestSuite) TearDownSuite() {
	s.ts.Close()
}

type jwksHandler struct {
	mux *http.ServeMux

	jwksResponse []byte
	tokenActive  bool
}

func newJWKSHandler() *jwksHandler {
	s := &jwksHandler{mux: http.NewServeMux()}
	s.mux.HandleFunc("/jwks", s.handleJWKS)
	s.mux.HandleFunc("/oauth2/introspect", s.handleIntrospect)

	return s
}

func (s *jwksHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *jwksHandler) handleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(s.jwksResponse)
}

func (s *jwksHandler) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	err := json.NewEncoder(w).Encode(Introspection{Active: s.tokenActive})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (s *handlerTestSuite) Test_ParseAndValidate_IntrospectionCache() {
	tokenString, err := s.token.SignedString(s.rsaPrivateKey)
	s.Require().NoError(err)

	var claims struct{}

	// Act
	s.jwks.tokenActive = true
	err = s.hdl.ValidateToken(context.Background(), tokenString, &claims, true)
	s.Require().NoError(err)

	s.jwks.tokenActive = false

	// Should not return an error because we use cache for GET requests
	err = s.hdl.ValidateToken(context.Background(), tokenString, &claims, true)
	s.Require().NoError(err)

	// Should invalidate cache for POST request
	err = s.hdl.ValidateToken(context.Background(), tokenString, &claims, false)
	s.Require().Error(err)
}
