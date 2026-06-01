package extauthz

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"log"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/extauthz/internal/clientdata"
	"github.com/openkcm/extauthz/internal/config"
	"github.com/openkcm/extauthz/internal/policies/cedarpolicy"
)

// =============================================================================
// Test Helper Functions
// =============================================================================

// createCertWithCustomSubject creates a certificate with a custom subject for testing.
// The subject is provided as a pkix.Name which will be properly encoded.
func createCertWithCustomSubject(subject pkix.Name, notBefore, notAfter time.Time) (string, error) {
	certX509 := x509.Certificate{
		SerialNumber:   big.NewInt(1),
		Subject:        subject,
		EmailAddresses: []string{"test@example.com"},
		NotBefore:      notBefore,
		NotAfter:       notAfter,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &certX509, &certX509, rsaPublicKey, rsaPrivateKey)
	if err != nil {
		return "", err
	}

	certPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  pemCertificateBlock,
		Bytes: certDER,
	}))

	return url.QueryEscape(certPEM), nil
}

// createCertWithSpecialCharsSubject creates a certificate with special characters
// that need RFC 2253 escaping in the subject.
func createCertWithSpecialCharsSubject(notBefore, notAfter time.Time) (string, error) {
	subject := pkix.Name{
		CommonName:   "test+user,org",    // contains + and ,
		Organization: []string{"Org<>;"}, // contains < > ;
	}
	return createCertWithCustomSubject(subject, notBefore, notAfter)
}

// createCertWithLeadingSpaceSubject creates a certificate with leading/trailing spaces
// that need RFC 2253 escaping.
func createCertWithLeadingSpaceSubject(notBefore, notAfter time.Time) (string, error) {
	subject := pkix.Name{
		CommonName: " spacey ", // leading and trailing space
	}
	return createCertWithCustomSubject(subject, notBefore, notAfter)
}

// createCertWithLeadingHashSubject creates a certificate with leading #
// that needs RFC 2253 escaping.
func createCertWithLeadingHashSubject(notBefore, notAfter time.Time) (string, error) {
	subject := pkix.Name{
		CommonName: "#hashtag",
	}
	return createCertWithCustomSubject(subject, notBefore, notAfter)
}

// setupTestServer creates a test server with the given policy and trusted subjects.
func setupTestServer(t *testing.T, policy string, trustedSubjects map[string]string) *Server {
	t.Helper()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyId"), []byte("key01"), 0644))
	require.NoError(t, createFileWithGeneratedKey(filepath.Join(dir, "key01.pem")))

	pe, err := cedarpolicy.NewEngine(cedarpolicy.WithBytes("test policies", []byte(policy)))
	require.NoError(t, err)

	signer, err := clientdata.NewSigner(&commoncfg.FeatureGates{}, &config.ClientData{
		SigningKeyIDFilePath: filepath.Join(dir, "keyId"),
	})
	require.NoError(t, err)

	srv, err := NewServer(WithClientDataSigner(signer), WithPolicyEngine(pe))
	require.NoError(t, err)

	srv.trustedSubjectToRegion = trustedSubjects

	t.Cleanup(func() {
		err := srv.Close()
		require.NoError(t, err)
	})

	require.NoError(t, srv.Start())

	return srv
}

// =============================================================================
// Test: parseCert
// =============================================================================

func TestParseCert(t *testing.T) {
	// Create a URL-encoded PEM public key (not a certificate) for testing
	rsaPublicKeyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: rsaPublicKeyDER,
	}))
	rsaPublicKeyURLEncoded := url.QueryEscape(rsaPublicKeyPEM)

	tests := []struct {
		name          string
		urlEncodedPem string
		wantError     bool
	}{
		{
			name:          "empty input returns error",
			urlEncodedPem: "",
			wantError:     true,
		},
		{
			name:          "invalid URL encoding returns error",
			urlEncodedPem: "bla%%20dlubb",
			wantError:     true,
		},
		{
			name:          "PEM block with wrong type returns error",
			urlEncodedPem: rsaPublicKeyURLEncoded,
			wantError:     true,
		},
		{
			name:          "malformed certificate content returns error",
			urlEncodedPem: urlEncodedInvalidCert,
			wantError:     true,
		},
		{
			name:          "valid certificate parses successfully",
			urlEncodedPem: x509CertPEMURLEncoded,
			wantError:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crt, err := parseCert(tc.urlEncodedPem)

			if tc.wantError {
				require.Error(t, err)
				require.Nil(t, crt)
			} else {
				require.NoError(t, err)
				require.NotNil(t, crt)
			}
		})
	}
}

// =============================================================================
// Test: mapHeader
// =============================================================================

func TestMapHeader(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantError bool
		want      map[string]string
	}{
		{
			name:      "empty string returns error",
			input:     "",
			wantError: true,
		},
		{
			name:      "value without equals sign returns error",
			input:     "FOO",
			wantError: true,
		},
		{
			name:  "single key-value pair",
			input: "FOO=bar",
			want:  map[string]string{"FOO": "bar"},
		},
		{
			name:  "multiple key-value pairs",
			input: "FOO=bar;BAZ=qux",
			want:  map[string]string{"FOO": "bar", "BAZ": "qux"},
		},
		{
			name:  "quoted values with semicolons preserved",
			input: `FOO=bar;BLA="bl;ub";BAZ="qux"`,
			want:  map[string]string{"FOO": "bar", "BLA": "bl;ub", "BAZ": "qux"},
		},
		{
			name:      "unclosed quote returns error",
			input:     `FOO=bar;BLA="bl;ub;BAZ="qux"`,
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mapHeader(tc.input)

			if tc.wantError {
				require.Error(t, err)
				require.Nil(t, got)
			} else {
				require.NoError(t, err)
				require.True(t, reflect.DeepEqual(got, tc.want), "expected: %+v, got: %+v", tc.want, got)
			}
		})
	}
}

// =============================================================================
// Test: splitPreservingQuotes
// =============================================================================

func TestSplitPreservingQuotes(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      []string
		wantError bool
	}{
		{
			name:  "empty string",
			input: "",
			want:  nil,
		},
		{
			name:  "no semicolons",
			input: "FOO=bar",
			want:  []string{"FOO=bar"},
		},
		{
			name:  "simple split",
			input: "FOO=bar;BAZ=qux",
			want:  []string{"FOO=bar", "BAZ=qux"},
		},
		{
			name:  "preserves semicolon in quotes",
			input: `FOO="bar;baz"`,
			want:  []string{`FOO="bar;baz"`},
		},
		{
			name:      "unclosed quote returns error",
			input:     `FOO="unclosed`,
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := splitPreservingQuotes(tc.input)

			if tc.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.want, got)
			}
		})
	}
}

// =============================================================================
// Test: extractSubject
// =============================================================================

func TestExtractSubject(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		want      string
		wantError bool
	}{
		{
			name:      "empty header",
			header:    "",
			wantError: true,
		},
		{
			name:      "no Subject field",
			header:    "Hash=123;Cert=abc",
			wantError: true,
		},
		{
			name:   "valid Subject",
			header: `Hash=123;Subject="CN=test"`,
			want:   "CN=test",
		},
		{
			name:   "Subject with multiple RDNs",
			header: `Hash=123;Subject="CN=test,O=org"`,
			want:   "CN=test,O=org",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractSubject(tc.header)

			if tc.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.want, got)
			}
		})
	}
}

// =============================================================================
// Test: escapeRFC2253
// =============================================================================

func TestEscapeRFC2253(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "no special characters",
			input: "simple",
			want:  "simple",
		},
		{
			name:  "comma escaped",
			input: "foo,bar",
			want:  `foo\,bar`,
		},
		{
			name:  "plus escaped",
			input: "foo+bar",
			want:  `foo\+bar`,
		},
		{
			name:  "double quote escaped",
			input: `foo"bar`,
			want:  `foo\"bar`,
		},
		{
			name:  "backslash escaped",
			input: `foo\bar`,
			want:  `foo\\bar`,
		},
		{
			name:  "less than escaped",
			input: "foo<bar",
			want:  `foo\<bar`,
		},
		{
			name:  "greater than escaped",
			input: "foo>bar",
			want:  `foo\>bar`,
		},
		{
			name:  "semicolon escaped",
			input: "foo;bar",
			want:  `foo\;bar`,
		},
		{
			name:  "equals escaped",
			input: "foo=bar",
			want:  `foo\=bar`,
		},
		{
			name:  "leading space escaped",
			input: " foo",
			want:  `\ foo`,
		},
		{
			name:  "trailing space escaped",
			input: "foo ",
			want:  `foo\ `,
		},
		{
			name:  "leading hash escaped",
			input: "#foo",
			want:  `\#foo`,
		},
		{
			name:  "multiple special characters",
			input: " #foo,bar+baz ",
			want:  `\ #foo\,bar\+baz\ `, // # is NOT escaped because it's at position 1, not 0
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := escapeRFC2253(tc.input)
			require.Equal(t, tc.want, got)
		})
	}
}

// =============================================================================
// Test: formatRDNSequence
// =============================================================================

func TestFormatRDNSequence(t *testing.T) {
	tests := []struct {
		name string
		rdns pkix.RDNSequence
		want string
	}{
		{
			name: "empty sequence",
			rdns: pkix.RDNSequence{},
			want: "",
		},
		{
			name: "single CN",
			rdns: pkix.RDNSequence{
				{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "test"}},
			},
			want: "CN=test",
		},
		{
			name: "CN and O in reverse order",
			rdns: pkix.RDNSequence{
				{{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "US"}},   // C
				{{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "Org"}}, // O
				{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "test"}}, // CN
			},
			want: "CN=test,O=Org,C=US",
		},
		{
			name: "unknown OID uses numeric form",
			rdns: pkix.RDNSequence{
				{{Type: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Value: "unknown"}},
			},
			want: "1.2.3.4.5=unknown",
		},
		{
			name: "multi-valued RDN joined with +",
			rdns: pkix.RDNSequence{
				{
					{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "test"},
					{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "org"},
				},
			},
			want: "CN=test+O=org",
		},
		{
			name: "all known OID types",
			rdns: pkix.RDNSequence{
				{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "cn"}},                        // CN
				{{Type: asn1.ObjectIdentifier{2, 5, 4, 7}, Value: "city"}},                      // L
				{{Type: asn1.ObjectIdentifier{2, 5, 4, 8}, Value: "state"}},                     // ST
				{{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "org"}},                      // O
				{{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "unit"}},                     // OU
				{{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "country"}},                   // C
				{{Type: asn1.ObjectIdentifier{2, 5, 4, 9}, Value: "street"}},                    // STREET
				{{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, Value: "dc"}},  // DC
				{{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}, Value: "user"}}, // UID
			},
			want: "UID=user,DC=dc,STREET=street,C=country,OU=unit,O=org,ST=state,L=city,CN=cn",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := formatRDNSequence(tc.rdns)
			require.Equal(t, tc.want, got)
		})
	}
}

// =============================================================================
// Test: formatSubject
// =============================================================================

func TestFormatSubject(t *testing.T) {
	validCert, err := createURLEncodedPEMCert(time.Now(), time.Now().Add(5*time.Minute))
	require.NoError(t, err)

	crt, err := parseCert(validCert)
	require.NoError(t, err)

	t.Run("valid certificate returns formatted subject", func(t *testing.T) {
		subject, err := formatSubject(crt)
		require.NoError(t, err)
		require.Equal(t, "CN=minime", subject)
	})

	t.Run("certificate with malformed RawSubject returns error", func(t *testing.T) {
		// Create a certificate with invalid ASN.1 in RawSubject
		badCert := &x509.Certificate{
			RawSubject: []byte{0xFF, 0xFF, 0xFF}, // Invalid ASN.1
		}

		subject, err := formatSubject(badCert)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse certificate subject")
		require.Empty(t, subject)
	})

	t.Run("certificate with empty subject after formatting returns error", func(t *testing.T) {
		// Create a certificate with valid but empty RDNSequence
		// An empty RDNSequence encodes to just the SEQUENCE tag with zero length
		emptyRDNSeq := pkix.RDNSequence{}
		rawSubject, err := asn1.Marshal(emptyRDNSeq)
		require.NoError(t, err)

		badCert := &x509.Certificate{
			RawSubject: rawSubject,
		}

		subject, err := formatSubject(badCert)
		require.Error(t, err)
		require.Contains(t, err.Error(), "certificate subject is empty after formatting")
		require.Empty(t, subject)
	})
}

// =============================================================================
// Test: formatIssuer
// =============================================================================

func TestFormatIssuer(t *testing.T) {
	validCert, err := createURLEncodedPEMCert(time.Now(), time.Now().Add(5*time.Minute))
	require.NoError(t, err)

	crt, err := parseCert(validCert)
	require.NoError(t, err)

	t.Run("valid certificate returns formatted issuer", func(t *testing.T) {
		issuer, err := formatIssuer(crt)
		require.NoError(t, err)
		require.Equal(t, "CN=minime", issuer) // Self-signed, issuer == subject
	})

	t.Run("certificate with malformed RawIssuer returns error", func(t *testing.T) {
		badCert := &x509.Certificate{
			RawIssuer: []byte{0xFF, 0xFF, 0xFF}, // Invalid ASN.1
		}

		issuer, err := formatIssuer(badCert)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse certificate issuer")
		require.Empty(t, issuer)
	})

	t.Run("certificate with empty issuer after formatting returns error", func(t *testing.T) {
		emptyRDNSeq := pkix.RDNSequence{}
		rawIssuer, err := asn1.Marshal(emptyRDNSeq)
		require.NoError(t, err)

		badCert := &x509.Certificate{
			RawIssuer: rawIssuer,
		}

		issuer, err := formatIssuer(badCert)
		require.Error(t, err)
		require.Contains(t, err.Error(), "certificate issuer is empty after formatting")
		require.Empty(t, issuer)
	})
}

// =============================================================================
// Test: checkClientCert
// =============================================================================

func TestCheckClientCert(t *testing.T) {
	x509CertPEMURLEncodedTooOld, err := createURLEncodedPEMCert(time.Now().Add(-10*time.Minute), time.Now().Add(-5*time.Minute))
	if err != nil {
		log.Fatalf("Error creating x509 certificate: %s", err)
	}

	x509CertPEMURLEncodedTooYoung, err := createURLEncodedPEMCert(time.Now().Add(5*time.Minute), time.Now().Add(10*time.Minute))
	if err != nil {
		log.Fatalf("Error creating x509 certificate: %s", err)
	}

	tests := []struct {
		name                string
		certHeader          string
		trustedSubjects     map[string]string
		wantCheckResultCode checkResultCode
		wantSubject         string
		wantRegion          string
		wantEmail           string
	}{
		{
			name:                "empty header returns UNAUTHENTICATED",
			certHeader:          "",
			wantCheckResultCode: UNAUTHENTICATED,
		},
		{
			name:                "invalid cert content returns UNAUTHENTICATED",
			certHeader:          "Hash=123;Subject=\"CN=minime\";Cert=blablubb",
			trustedSubjects:     map[string]string{"CN=minime": "minime-region"},
			wantCheckResultCode: UNAUTHENTICATED,
		},
		{
			name:                "missing Cert field returns UNAUTHENTICATED",
			certHeader:          "Hash=123;Subject=\"foo\"",
			wantCheckResultCode: UNAUTHENTICATED,
		},
		{
			name:                "expired certificate returns DENIED",
			certHeader:          "Hash=123;Subject=\"CN=minime\";Cert=" + x509CertPEMURLEncodedTooOld,
			trustedSubjects:     map[string]string{"CN=minime": "minime-region"},
			wantCheckResultCode: DENIED,
		},
		{
			name:                "not-yet-valid certificate returns DENIED",
			certHeader:          "Hash=123;Subject=\"CN=minime\";Cert=" + x509CertPEMURLEncodedTooYoung,
			trustedSubjects:     map[string]string{"CN=minime": "minime-region"},
			wantCheckResultCode: DENIED,
		},
		{
			name:                "valid certificate returns ALLOWED",
			certHeader:          "Hash=123;Subject=\"CN=minime\";Cert=" + x509CertPEMURLEncoded,
			trustedSubjects:     map[string]string{"CN=minime": "minime-region"},
			wantCheckResultCode: ALLOWED,
			wantSubject:         "CN=minime",
			wantEmail:           "me@minime.com",
			wantRegion:          "minime-region",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := setupTestServer(t, cedarpolicies, tc.trustedSubjects)
			result := srv.checkClientCert(t.Context(), tc.certHeader, "GET", "our.service.com", "/foo/bar")

			require.Equal(t, tc.wantCheckResultCode, result.is, "unexpected result code, info: %s", result.info)

			if tc.wantSubject != "" {
				require.Equal(t, tc.wantSubject, result.subject)
			}
			if tc.wantEmail != "" {
				require.Equal(t, tc.wantEmail, result.email)
			}
			if tc.wantRegion != "" {
				require.Equal(t, tc.wantRegion, result.region)
			}
		})
	}
}

func TestCheckClientCertHeaderParsing(t *testing.T) {
	tests := []struct {
		name                string
		certHeader          string
		wantCheckResultCode checkResultCode
	}{
		{
			name:                "invalid header format without equals returns UNAUTHENTICATED",
			certHeader:          "InvalidHeaderWithoutEquals",
			wantCheckResultCode: UNAUTHENTICATED,
		},
		{
			name:                "unclosed quote in header returns UNAUTHENTICATED",
			certHeader:          "Hash=123;Subject=\"unclosed",
			wantCheckResultCode: UNAUTHENTICATED,
		},
		{
			name:                "missing Cert field in header returns UNAUTHENTICATED",
			certHeader:          "Hash=123;Subject=\"CN=minime\"",
			wantCheckResultCode: UNAUTHENTICATED,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := setupTestServer(t, cedarpolicies, map[string]string{"CN=minime": "minime-region"})
			result := srv.checkClientCert(t.Context(), tc.certHeader, "GET", "our.service.com", "/foo/bar")

			require.Equal(t, tc.wantCheckResultCode, result.is, "unexpected result code, info: %s", result.info)
		})
	}
}

func TestCheckClientCertSubjectValidation(t *testing.T) {
	validCert, err := createURLEncodedPEMCert(time.Now().Add(-5*time.Minute), time.Now().Add(5*time.Minute))
	require.NoError(t, err)

	tests := []struct {
		name                string
		certHeader          string
		trustedSubjects     map[string]string
		wantCheckResultCode checkResultCode
	}{
		{
			name:                "mismatched header subject and cert subject returns DENIED",
			certHeader:          "Hash=123;Subject=\"CN=different\";Cert=" + validCert,
			trustedSubjects:     map[string]string{"CN=minime": "minime-region"},
			wantCheckResultCode: DENIED,
		},
		{
			name:                "missing Subject header falls back to cert subject",
			certHeader:          "Hash=123;Cert=" + validCert,
			trustedSubjects:     map[string]string{"CN=minime": "minime-region"},
			wantCheckResultCode: ALLOWED,
		},
		{
			name:                "untrusted subject returns DENIED",
			certHeader:          "Hash=123;Subject=\"CN=minime\";Cert=" + validCert,
			trustedSubjects:     map[string]string{"CN=trusted": "trusted-region"},
			wantCheckResultCode: DENIED,
		},
		{
			name:                "empty trusted subjects map returns DENIED",
			certHeader:          "Hash=123;Subject=\"CN=minime\";Cert=" + validCert,
			trustedSubjects:     map[string]string{},
			wantCheckResultCode: DENIED,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := setupTestServer(t, cedarpolicies, tc.trustedSubjects)
			result := srv.checkClientCert(t.Context(), tc.certHeader, "GET", "our.service.com", "/foo/bar")

			require.Equal(t, tc.wantCheckResultCode, result.is, "unexpected result code, info: %s", result.info)
		})
	}
}

func TestCheckClientCertPolicyEngineErrors(t *testing.T) {
	validCert, err := createURLEncodedPEMCert(time.Now().Add(-5*time.Minute), time.Now().Add(5*time.Minute))
	require.NoError(t, err)

	t.Run("policy engine denies request returns DENIED", func(t *testing.T) {
		// Policy that always denies
		denyPolicy := `permit(principal, action, resource) when { false };`
		srv := setupTestServer(t, denyPolicy, map[string]string{"CN=minime": "minime-region"})

		result := srv.checkClientCert(t.Context(),
			"Hash=123;Subject=\"CN=minime\";Cert="+validCert,
			"GET", "our.service.com", "/foo/bar")

		require.Equal(t, DENIED, result.is, "expected DENIED from policy engine, info: %s", result.info)
	})
}

func TestCheckClientCertWithSpecialCharacters(t *testing.T) {
	// Use an allow-all policy for testing special character handling
	allowAllPolicy := `permit(principal, action, resource);`

	// Test RFC 2253 escaping in real certificate flow
	t.Run("certificate with special chars in subject", func(t *testing.T) {
		specialCert, err := createCertWithSpecialCharsSubject(
			time.Now().Add(-5*time.Minute),
			time.Now().Add(5*time.Minute),
		)
		require.NoError(t, err)

		// The formatted subject will have escaped characters
		// CN=test+user,org becomes CN=test\+user\,org
		trustedSubjects := map[string]string{`CN=test\+user\,org,O=Org\<\>\;`: "special-region"}
		srv := setupTestServer(t, allowAllPolicy, trustedSubjects)

		result := srv.checkClientCert(t.Context(),
			"Hash=123;Cert="+specialCert,
			"GET", "our.service.com", "/foo/bar")

		require.Equal(t, ALLOWED, result.is, "expected ALLOWED, info: %s", result.info)
	})

	t.Run("certificate with leading space in subject", func(t *testing.T) {
		spaceCert, err := createCertWithLeadingSpaceSubject(
			time.Now().Add(-5*time.Minute),
			time.Now().Add(5*time.Minute),
		)
		require.NoError(t, err)

		// Leading/trailing spaces are escaped
		trustedSubjects := map[string]string{`CN=\ spacey\ `: "space-region"}
		srv := setupTestServer(t, allowAllPolicy, trustedSubjects)

		result := srv.checkClientCert(t.Context(),
			"Hash=123;Cert="+spaceCert,
			"GET", "our.service.com", "/foo/bar")

		require.Equal(t, ALLOWED, result.is, "expected ALLOWED, info: %s", result.info)
	})

	t.Run("certificate with leading hash in subject", func(t *testing.T) {
		hashCert, err := createCertWithLeadingHashSubject(
			time.Now().Add(-5*time.Minute),
			time.Now().Add(5*time.Minute),
		)
		require.NoError(t, err)

		// Leading # is escaped
		trustedSubjects := map[string]string{`CN=\#hashtag`: "hash-region"}
		srv := setupTestServer(t, allowAllPolicy, trustedSubjects)

		result := srv.checkClientCert(t.Context(),
			"Hash=123;Cert="+hashCert,
			"GET", "our.service.com", "/foo/bar")

		require.Equal(t, ALLOWED, result.is, "expected ALLOWED, info: %s", result.info)
	})
}

// TestCheckClientCertUncoveredPaths documents the coverage limitations for checkClientCert.
//
// The following paths in checkClientCert cannot be reached through integration tests
// because they require certificates that are malformed in specific ways that still
// pass x509.ParseCertificate validation:
//
// 1. formatSubject error path (lines 257-261):
//    - Requires a certificate where RawSubject is invalid ASN.1 or empty after formatting
//    - x509.ParseCertificate validates RawSubject during parsing, so this path is
//      effectively dead code in the integration context
//    - COVERED BY: TestFormatSubject unit tests
//
// 2. Empty subject check (lines 271-275):
//    - formatSubject already returns error for empty subjects, so this check is
//      defense-in-depth that can only be triggered if formatSubject behavior changes
//    - COVERED BY: TestFormatSubject/certificate_with_empty_subject_after_formatting_returns_error
//
// 3. formatIssuer error path (lines 315-319):
//    - Same issue as formatSubject
//    - COVERED BY: TestFormatIssuer unit tests
//
// 4. Policy engine error path (lines 342-346):
//    - Would require the Cedar policy engine to return an error during Check()
//    - The only error paths in Check() are option application errors or json.Marshal failures
//    - Both are extremely unlikely in normal operation
//    - CONSIDERED LOW RISK: Policy engine is external dependency with its own test coverage
//
// Total checkClientCert coverage: 84.5%
// Remaining 15.5% is defense-in-depth code that requires extraordinary conditions

func TestCheckClientCertCertificateWithNoEmail(t *testing.T) {
	// Use an allow-all policy for this test
	allowAllPolicy := `permit(principal, action, resource);`

	// Create a certificate without email addresses
	certX509 := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "noemail",
		},
		// No EmailAddresses
		NotBefore: time.Now().Add(-5 * time.Minute),
		NotAfter:  time.Now().Add(5 * time.Minute),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &certX509, &certX509, rsaPublicKey, rsaPrivateKey)
	require.NoError(t, err)

	certPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  pemCertificateBlock,
		Bytes: certDER,
	}))
	noEmailCert := url.QueryEscape(certPEM)

	t.Run("certificate without email returns ALLOWED with empty email", func(t *testing.T) {
		srv := setupTestServer(t, allowAllPolicy, map[string]string{"CN=noemail": "noemail-region"})

		result := srv.checkClientCert(t.Context(),
			"Hash=123;Subject=\"CN=noemail\";Cert="+noEmailCert,
			"GET", "our.service.com", "/foo/bar")

		require.Equal(t, ALLOWED, result.is, "expected ALLOWED, info: %s", result.info)
		require.Equal(t, "CN=noemail", result.subject)
		require.Empty(t, result.email)
		require.Equal(t, "noemail-region", result.region)
	})
}
