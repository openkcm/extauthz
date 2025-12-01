package extauthz

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/gogo/googleapis/google/rpc"
	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/openkcm/extauthz/internal/clientdata"
	"github.com/openkcm/extauthz/internal/config"
	"github.com/openkcm/extauthz/internal/policies/cedarpolicy"
	"github.com/openkcm/extauthz/internal/session"
)

const (
	cedarpolicies = `
permit (
	principal == Subject::"me",
	action == Action::"GET",
	resource is Route
) when {
	context.route like "*.service.com/foo/bar*"
	&& context.issuer like "https://127.0.0.1:*"
};

permit (
	principal == Subject::"CN=minime",
	action == Action::"GET",
	resource is Route
) when {
	context.route == "our.service.com/foo/bar"
};

permit (
	principal == Subject::"mySessionMe",
	action == Action::"GET",
	resource is Route
) when {
	context.route like "*.service.com/cmk/v1*"
	&& context.issuer like "https://127.0.0.1:*"
};

// Registry Service
permit (
    principal,
    action in [Action::"GET", Action::"PUT", Action::"POST"],
    resource is Route
) when {
    principal in [
        Subject::"CN=minime"
    ] 
    && context.type == "x509" 
    && context.route like "*/kms.api.cmk.registry.*.v1.Service/*"
};
`
)

// createFileWithGeneratedKey is used in tests to generate a new signing key.
func createFileWithGeneratedKey(filepath string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	// Convert to PKCS#1 ASN.1 DER form
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// Create a PEM block
	privBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privDER,
	}

	// Create or overwrite the output file
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write the PEM block to file
	err = pem.Encode(file, privBlock)
	if err != nil {
		return err
	}

	return nil
}

func TestCheck(t *testing.T) {
	// Arrange
	defaultFeatureGates := &commoncfg.FeatureGates{
		clientdata.EnrichHeaderWithClientRegion: true,
		clientdata.EnrichHeaderWithClientType:   true,
	}

	// create the test cases
	tests := []struct {
		name            string
		featureGates    *commoncfg.FeatureGates
		trustedSubjects map[string]string
		request         *envoy_auth.CheckRequest
		setupMocks      func(*MockSessionManager)
		wantError       bool
		wantCode        rpc.Code
		want            *envoy_auth.CheckResponse
	}{
		{
			name:         "zero values",
			featureGates: defaultFeatureGates,
			wantError:    false,
			wantCode:     rpc.UNAUTHENTICATED,
		}, {
			name:         "missing client certificate and authorization header",
			featureGates: defaultFeatureGates,
			request: &envoy_auth.CheckRequest{
				Attributes: &envoy_auth.AttributeContext{
					Request: &envoy_auth.AttributeContext_Request{
						Http: &envoy_auth.AttributeContext_HttpRequest{
							Path: "/foo/bar"}}}},
			wantError: false,
			wantCode:  rpc.UNAUTHENTICATED,
		}, {
			name:         "with invalid client certificate",
			featureGates: defaultFeatureGates,
			request: &envoy_auth.CheckRequest{
				Attributes: &envoy_auth.AttributeContext{
					Request: &envoy_auth.AttributeContext_Request{
						Http: &envoy_auth.AttributeContext_HttpRequest{
							Path:    "/foo/bar",
							Headers: map[string]string{HeaderForwardedClientCert: "client-cert"}}}}},
			wantError: false,
			wantCode:  rpc.UNAUTHENTICATED,
		}, {
			name:            "with valid client certificate",
			featureGates:    defaultFeatureGates,
			trustedSubjects: map[string]string{"CN=minime": "minime-region"},
			request: &envoy_auth.CheckRequest{
				Attributes: &envoy_auth.AttributeContext{
					Request: &envoy_auth.AttributeContext_Request{
						Http: &envoy_auth.AttributeContext_HttpRequest{
							Method:  "GET",
							Host:    "our.service.com",
							Path:    "/foo/bar",
							Headers: map[string]string{HeaderForwardedClientCert: "Hash=123;Subject=\"CN=minime\";Cert=" + x509CertPEMURLEncoded}}}}},
			wantError: false,
			wantCode:  rpc.OK,
		}, {
			name:            "with valid client certificate - different subject",
			featureGates:    defaultFeatureGates,
			trustedSubjects: map[string]string{"CN=minime": "minime-region"},
			request: &envoy_auth.CheckRequest{
				Attributes: &envoy_auth.AttributeContext{
					Request: &envoy_auth.AttributeContext_Request{
						Http: &envoy_auth.AttributeContext_HttpRequest{
							Method:  "GET",
							Host:    "our.service.com",
							Path:    "/foo/bar",
							Headers: map[string]string{HeaderForwardedClientCert: "Hash=123;Subject=\"CN=daummy\";Cert=" + x509CertPEMURLEncoded}}}}},
			wantError: false,
			wantCode:  rpc.PERMISSION_DENIED,
		}, {
			name:            "with disallowed client certificate",
			featureGates:    defaultFeatureGates,
			trustedSubjects: map[string]string{"CN=minime": "minime-region"},
			request: &envoy_auth.CheckRequest{
				Attributes: &envoy_auth.AttributeContext{
					Request: &envoy_auth.AttributeContext_Request{
						Http: &envoy_auth.AttributeContext_HttpRequest{
							Path:    "/foo/bar",
							Headers: map[string]string{HeaderForwardedClientCert: "Hash=123;Subject=\"CN=austin\";Cert=" + x509CertPEMURLEncoded}}}}},
			wantError: false,
			wantCode:  rpc.PERMISSION_DENIED,
		}, {
			name:         "with authorization header",
			featureGates: defaultFeatureGates,
			request: &envoy_auth.CheckRequest{
				Attributes: &envoy_auth.AttributeContext{
					Request: &envoy_auth.AttributeContext_Request{
						Http: &envoy_auth.AttributeContext_HttpRequest{
							Path:    "/foo/bar",
							Headers: map[string]string{"authorization": "Bearer token"}}}}},
			wantError: false,
			wantCode:  rpc.UNAUTHENTICATED,
		}, {
			name:         "with session cookie",
			featureGates: defaultFeatureGates,
			request: &envoy_auth.CheckRequest{
				Attributes: &envoy_auth.AttributeContext{
					Request: &envoy_auth.AttributeContext_Request{
						Http: &envoy_auth.AttributeContext_HttpRequest{
							Method:  "GET",
							Host:    "our.service.com",
							Path:    "/cmk/v1/myTenantID/bar",
							Headers: map[string]string{"cookie": "__Host-Http-SESSION=mySessionID"}}}}},
			setupMocks: func(msm *MockSessionManager) {
				msm.On("GetSession", mock.Anything, "mySessionID", "myTenantID", mock.Anything).
					Return(&session.Session{
						Valid:      true,
						Subject:    "mySessionMe",
						Issuer:     "https://127.0.0.1:8443",
						GivenName:  "Chris",
						FamilyName: "Burkert",
					}, nil)
			},
			wantError: false,
			wantCode:  rpc.OK,
		}, {
			name:            "registry service - system",
			featureGates:    defaultFeatureGates,
			trustedSubjects: map[string]string{"CN=minime": "minime-region"},
			request: &envoy_auth.CheckRequest{
				Attributes: &envoy_auth.AttributeContext{
					Request: &envoy_auth.AttributeContext_Request{
						Http: &envoy_auth.AttributeContext_HttpRequest{
							Method:  "POST",
							Host:    "our.service.com",
							Path:    "/kms.api.cmk.registry.system.v1.Service/RegisterSystem",
							Headers: map[string]string{HeaderForwardedClientCert: "Hash=123;Subject=\"CN=minime\";Cert=" + x509CertPEMURLEncoded}}}}},
			wantError: false,
			wantCode:  rpc.OK,
		}, {
			name:            "registry service - tenant",
			featureGates:    defaultFeatureGates,
			trustedSubjects: map[string]string{"CN=minime": "minime-region"},
			request: &envoy_auth.CheckRequest{
				Attributes: &envoy_auth.AttributeContext{
					Request: &envoy_auth.AttributeContext_Request{
						Http: &envoy_auth.AttributeContext_HttpRequest{
							Method:  "POST",
							Host:    "our.service.com",
							Path:    "/kms.api.cmk.registry.tenant.v1.Service/RegisterTenant",
							Headers: map[string]string{HeaderForwardedClientCert: "Hash=123;Subject=\"CN=minime\";Cert=" + x509CertPEMURLEncoded}}}}},
			wantError: false,
			wantCode:  rpc.OK,
		},
	}

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyId"), []byte("key01"), 0644))

	err := createFileWithGeneratedKey(filepath.Join(dir, "key01.pem"))
	require.NoError(t, err)

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			mockSessionManager := new(MockSessionManager)
			if tc.setupMocks != nil {
				tc.setupMocks(mockSessionManager)
			}

			pe, err := cedarpolicy.NewEngine(cedarpolicy.WithBytes("my policies", []byte(cedarpolicies)))
			if err != nil {
				t.Fatalf("could not create policy engine: %s", err)
			}

			featureFlags := &commoncfg.FeatureGates{
				clientdata.EnrichHeaderWithClientRegion: true,
				clientdata.EnrichHeaderWithClientType:   true,
			}

			signer, err := clientdata.NewSigner(featureFlags, &config.ClientData{
				SigningKeyIDFilePath: filepath.Join(dir, "keyId"),
			})
			if err != nil {
				t.Fatalf("could not create clientdata signer: %s", err)
			}

			srv, err := NewServer(
				WithSessionPathPrefixes([]string{"/cmk/v1"}),
				WithSessionManager(mockSessionManager),
				WithClientDataSigner(signer),
				WithPolicyEngine(pe),
				WithFeatureGates(tc.featureGates))
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

			srv.trustedSubjectToRegion = tc.trustedSubjects

			// Act
			got, err := srv.Check(t.Context(), tc.request)

			// Assert
			if tc.wantError {
				if err == nil {
					t.Error("expected error, but got nil")
				}

				if got != nil {
					t.Errorf("expected nil response, but got: %+v", got)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %s", err)
				} else {
					if got.GetStatus().GetCode() != int32(tc.wantCode) {
						t.Errorf("expected code: %v, got: %v", tc.wantCode, got.GetStatus().GetCode())
					}
				}
			}
		})
	}
}

func TestSplitCertHeader(t *testing.T) {
	// create the test cases
	tests := []struct {
		name      string
		input     string
		wantError bool
		want      []string
	}{
		{
			name:      "zero values",
			input:     ``,
			wantError: false,
			want:      []string{``},
		}, {
			name:  "one cert",
			input: `A=b;C="d";E=f`,
			want:  []string{`A=b;C="d";E=f`},
		}, {
			name:  "two certs",
			input: `A=b;C="d";E=f,1=2;3="4";5=6`,
			want:  []string{`A=b;C="d";E=f`, `1=2;3="4";5=6`},
		}, {
			name:  "quoted spaces",
			input: `A=b;C="d,";E=f,1=2;3="4,";5=6`,
			want:  []string{`A=b;C="d,";E=f`, `1=2;3="4,";5=6`},
		}, {
			name:      "invalid quoted spaces",
			input:     `A=b;C="d,;E=f,1=2;3="4,";5=6`,
			wantError: true,
		},
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			got, err := splitCertHeader(tc.input)

			// Assert
			if tc.wantError {
				if err == nil {
					t.Error("expected error, but got nil")
				}

				if got != nil {
					t.Errorf("expected nil array, but got: %+v", got)
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
