package extauthz

import (
	"crypto/x509"
	"log"
	"reflect"
	"testing"
	"time"

	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/openkcm/extauthz/internal/clientdata"
	"github.com/openkcm/extauthz/internal/policies/cedarpolicy"
)

func TestParseCert(t *testing.T) {
	// create the test cases
	tests := []struct {
		name          string
		urlEncodedPem string
		wantError     bool
		want          *x509.Certificate
	}{
		{
			name:      "zero values",
			wantError: true,
		}, {
			name:          "invalid encoding",
			urlEncodedPem: "bla%%20dlubb",
			wantError:     true,
		}, {
			name:          "not a certificate",
			urlEncodedPem: rsaPublicKeyPEMURLEncoded,
			wantError:     true,
		}, {
			name:          "invalid certificate",
			urlEncodedPem: urlEncodedInvalidCert,
			wantError:     true,
		}, {
			name:          "valid certificate",
			urlEncodedPem: x509CertPEMURLEncoded,
			wantError:     false,
		},
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			crt, err := parseCert(tc.urlEncodedPem)

			// Assert
			if tc.wantError {
				if err == nil {
					t.Error("expected error, but got nil")
				}

				if crt != nil {
					t.Errorf("expected nil certificate, but got: %+v", crt)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %s", err)
				}
			}
		})
	}
}

func TestCheckClientCert(t *testing.T) {
	x509CertPEMURLEncodedTooOld, err := createURLEncodedPEMCert(time.Now().Add(-10*time.Minute), time.Now().Add(-5*time.Minute))
	if err != nil {
		log.Fatalf("Error creating x509 certificate: %s", err)
	}

	x509CertPEMURLEncodedTooYoung, err := createURLEncodedPEMCert(time.Now().Add(5*time.Minute), time.Now().Add(10*time.Minute))
	if err != nil {
		log.Fatalf("Error creating x509 certificate: %s", err)
	}

	// create the test cases
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
			name:                "zero values",
			wantCheckResultCode: UNAUTHENTICATED,
		}, {
			name:                "invalid cert",
			certHeader:          "Hash=123;Subject=\"CN=minime\";Cert=blablubb",
			trustedSubjects:     map[string]string{"CN=minime": "minime-region"},
			wantCheckResultCode: UNAUTHENTICATED,
		}, {
			name:                "test",
			certHeader:          "Hash=123;Subject=\"CN=minime\";Cert=blablubb",
			trustedSubjects:     nil,
			wantCheckResultCode: DENIED,
		}, {
			name:                "permission denied",
			certHeader:          "Hash=123;Subject=\"foo\"",
			wantCheckResultCode: DENIED,
		}, {
			name:                "cert too old",
			certHeader:          "Hash=123;Subject=\"CN=minime\";Cert=" + x509CertPEMURLEncodedTooOld,
			trustedSubjects:     map[string]string{"CN=minime": "minime-region"},
			wantCheckResultCode: DENIED,
		}, {
			name:                "cert too young",
			certHeader:          "Hash=123;Subject=\"CN=minime\";Cert=" + x509CertPEMURLEncodedTooYoung,
			trustedSubjects:     map[string]string{"CN=minime": "minime-region"},
			wantCheckResultCode: DENIED,
		}, {
			name:                "authorized",
			certHeader:          "Hash=123;Subject=\"CN=minime\";Cert=" + x509CertPEMURLEncoded,
			trustedSubjects:     map[string]string{"CN=minime": "minime-region"},
			wantCheckResultCode: ALLOWED,
			wantSubject:         "CN=minime",
			wantEmail:           "me@minime.com",
			wantRegion:          "minime-region",
		},
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			pe, err := cedarpolicy.NewEngine(cedarpolicy.WithBytes("my policies", []byte(cedarpolicies)))
			if err != nil {
				t.Fatalf("could not create policy engine: %s", err)
			}

			clientdataFactory := clientdata.NewFactoryWithSigningKey(&commoncfg.FeatureGates{
				clientdata.DisableClientDataComputation: true,
			}, nil)
			srv, err := NewServer(WithClientDataFactory(clientdataFactory), WithPolicyEngine(pe))
			if err != nil {
				t.Fatalf("could not create server: %s", err)
			}

			srv.trustedSubjectToRegion = tc.trustedSubjects

			// Act
			result := srv.checkClientCert(t.Context(), tc.certHeader, "GET", "my.service.com", "/foo/bar")

			// Assert
			if result.subject != tc.wantSubject {
				t.Errorf("expected: %v, got: %v", tc.wantSubject, result.subject)
			}

			if result.email != tc.wantEmail {
				t.Errorf("expected: %v, got: %v", tc.wantEmail, result.email)
			}

			if result.region != tc.wantRegion {
				t.Errorf("expected: %v, got: %v", tc.wantRegion, result.region)
			}
		})
	}
}

func TestMapHeader(t *testing.T) {
	// create the test cases
	tests := []struct {
		name      string
		input     string
		wantError bool
		want      map[string]string
	}{
		{
			name:      "zero values",
			input:     ``,
			wantError: true,
		}, {
			name:      "invalid value",
			input:     `FOO`,
			wantError: true,
		}, {
			name:  "one pair",
			input: `FOO=bar`,
			want:  map[string]string{"FOO": "bar"},
		}, {
			name:  "several pairs",
			input: `FOO=bar;BAZ=qux`,
			want:  map[string]string{"FOO": "bar", "BAZ": "qux"},
		}, {
			name:  "quoted pairs",
			input: `FOO=bar;BLA="bl;ub";BAZ="qux"`,
			want:  map[string]string{"FOO": "bar", "BLA": "bl;ub", "BAZ": "qux"},
		}, {
			name:      "invalid quoted pairs",
			input:     `FOO=bar;BLA="bl;ub;BAZ="qux"`,
			wantError: true,
		},
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			got, err := mapHeader(tc.input)

			// Assert
			if tc.wantError {
				if err == nil {
					t.Error("expected error, but got nil")
				}

				if got != nil {
					t.Errorf("expected nil map, but got: %+v", got)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %s", err)
				} else {
					if !reflect.DeepEqual(got, tc.want) {
						t.Errorf("expected: %+v, got: %+v", tc.want, got)
					}
				}
			}
		})
	}
}
