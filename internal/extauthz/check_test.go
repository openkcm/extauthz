package extauthz

import (
	"reflect"
	"testing"

	"github.com/gogo/googleapis/google/rpc"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/openkcm/extauthz/internal/policy"
	"github.com/openkcm/extauthz/internal/signing"
)

var cedarpolicies = `
permit (
	principal == Subject::"me",
	action == Action::"GET",
	resource is Route
) when {
	context.route == "my.service.com/foo/bar" && context.issuer like "https://127.0.0.1:*"
};

permit (
	principal == Subject::"CN=minime",
	action == Action::"GET",
	resource is Route
) when {
	context.route == "my.service.com/foo/bar"
};
`

func TestCheck(t *testing.T) {
	// Arrange
	signingKey, err := signing.NewKey(t.Context())
	if err != nil {
		t.Fatalf("failed to create signing key: %s", err)
	}

	// create the test cases
	tests := []struct {
		name            string
		trustedSubjects map[string]string
		request         *envoy_auth.CheckRequest
		wantError       bool
		wantCode        rpc.Code
		want            *envoy_auth.CheckResponse
	}{
		{
			name:      "zero values",
			wantError: false,
			wantCode:  rpc.UNAUTHENTICATED,
		}, {
			name: "missing client certificate and authorization header",
			request: &envoy_auth.CheckRequest{
				Attributes: &envoy_auth.AttributeContext{
					Request: &envoy_auth.AttributeContext_Request{
						Http: &envoy_auth.AttributeContext_HttpRequest{
							Path: "/foo/bar"}}}},
			wantError: false,
			wantCode:  rpc.UNAUTHENTICATED,
		}, {
			name: "with invalid client certificate",
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
			trustedSubjects: map[string]string{"CN=minime": "minime-region"},
			request: &envoy_auth.CheckRequest{
				Attributes: &envoy_auth.AttributeContext{
					Request: &envoy_auth.AttributeContext_Request{
						Http: &envoy_auth.AttributeContext_HttpRequest{
							Method:  "GET",
							Host:    "my.service.com",
							Path:    "/foo/bar",
							Headers: map[string]string{HeaderForwardedClientCert: "Hash=123;Subject=\"CN=minime\";Cert=" + x509CertPEMURLEncoded}}}}},
			wantError: false,
			wantCode:  rpc.OK,
		}, {
			name:            "with disallowed client certificate",
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
			name: "with authorization header",
			request: &envoy_auth.CheckRequest{
				Attributes: &envoy_auth.AttributeContext{
					Request: &envoy_auth.AttributeContext_Request{
						Http: &envoy_auth.AttributeContext_HttpRequest{
							Path:    "/foo/bar",
							Headers: map[string]string{"authorization": "Bearer token"}}}}},
			wantError: false,
			wantCode:  rpc.UNAUTHENTICATED,
		},
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			pe, err := policy.NewEngine(policy.WithBytes("my policies", []byte(cedarpolicies)))
			if err != nil {
				t.Fatalf("could not create policy engine: %s", err)
			}
			srv, err := NewServer(signingKey.Private,
				WithPolicyEngine(pe),
				WithEnrichHeaderWithType(true),
				WithEnrichHeaderWithRegion(true))
			if err != nil {
				t.Fatalf("could not create server: %s", err)
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
