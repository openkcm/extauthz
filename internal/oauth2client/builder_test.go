package oauth2client_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/extauthz/internal/oauth2client"
)

// validOAuth2Template returns a minimal valid OAuth2 config for testing.
func validOAuth2Template() commoncfg.OAuth2 {
	return commoncfg.OAuth2{
		Credentials: commoncfg.OAuth2Credentials{
			ClientID: commoncfg.SourceRef{
				Source: commoncfg.EmbeddedSourceValue,
				Value:  "template-client-id",
			},
			AuthMethod: commoncfg.OAuth2ClientSecretPost,
			ClientSecret: &commoncfg.SourceRef{
				Source: commoncfg.EmbeddedSourceValue,
				Value:  "test-secret",
			},
		},
	}
}

func TestNewBuilder_ReturnsNonNilBuilder(t *testing.T) {
	t.Parallel()

	// Arrange
	template := commoncfg.OAuth2{}

	// Act
	builder := oauth2client.NewBuilder(template)

	// Assert
	assert.NotNil(t, builder)
}

func TestBuilder_SuccessWithValidConfig(t *testing.T) {
	t.Parallel()

	// Arrange
	template := validOAuth2Template()
	builder := oauth2client.NewBuilder(template)

	// Act
	client, err := builder("override-client-id")

	// Assert
	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.NotNil(t, client.Transport, "client should have OAuth2 transport configured")
}

func TestBuilder_OverridesClientID(t *testing.T) {
	t.Parallel()

	// Arrange
	template := validOAuth2Template()
	builder := oauth2client.NewBuilder(template)
	expectedClientID := "overridden-client-id"

	// Create a test server that captures the client_id from the request
	var capturedClientID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		q, _ := url.ParseQuery(string(body))
		capturedClientID = q.Get("client_id")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Act
	client, err := builder(expectedClientID)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL, strings.NewReader("grant_type=client_credentials"))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Assert
	assert.Equal(t, expectedClientID, capturedClientID)
}

func TestBuilder_DoesNotMutateTemplate(t *testing.T) {
	t.Parallel()

	// Arrange
	originalClientID := "original-client-id"
	template := commoncfg.OAuth2{
		Credentials: commoncfg.OAuth2Credentials{
			ClientID: commoncfg.SourceRef{
				Source: commoncfg.EmbeddedSourceValue,
				Value:  originalClientID,
			},
			AuthMethod: commoncfg.OAuth2ClientSecretPost,
			ClientSecret: &commoncfg.SourceRef{
				Source: commoncfg.EmbeddedSourceValue,
				Value:  "test-secret",
			},
		},
	}
	builder := oauth2client.NewBuilder(template)

	// Act - call builder with different clientID
	_, err := builder("new-client-id")
	require.NoError(t, err)

	// Assert - template should be unchanged
	assert.Equal(t, originalClientID, template.Credentials.ClientID.Value)
	assert.Equal(t, commoncfg.EmbeddedSourceValue, template.Credentials.ClientID.Source)
}

func TestBuilder_MultipleCallsWorkIndependently(t *testing.T) {
	t.Parallel()

	// Arrange
	template := validOAuth2Template()
	builder := oauth2client.NewBuilder(template)

	// Act - create two clients with different IDs
	client1, err1 := builder("client-id-1")
	client2, err2 := builder("client-id-2")

	// Assert - both should succeed
	require.NoError(t, err1)
	require.NoError(t, err2)
	require.NotNil(t, client1)
	require.NotNil(t, client2)

	// Verify they are different clients
	assert.NotSame(t, client1, client2)

	// Verify each has the correct clientID via integration test
	verifyClientID := func(client *http.Client, expectedID string) {
		t.Helper()
		var capturedID string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			q, _ := url.ParseQuery(string(body))
			capturedID = q.Get("client_id")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL, strings.NewReader("grant_type=client_credentials"))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, expectedID, capturedID)
	}

	verifyClientID(client1, "client-id-1")
	verifyClientID(client2, "client-id-2")
}

func TestBuilder_PropagatesError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		template    commoncfg.OAuth2
		clientID    string
		wantErr     bool
		errContains string
	}{
		{
			name: "error_no_auth_method",
			template: commoncfg.OAuth2{
				Credentials: commoncfg.OAuth2Credentials{
					AuthMethod: commoncfg.OAuth2ClientSecretPost,
					// Missing ClientSecret - will cause "no client authentication method" error
				},
			},
			clientID:    "test-client",
			wantErr:     true,
			errContains: "no client authentication method provided",
		},
		{
			name: "error_invalid_mtls_config",
			template: commoncfg.OAuth2{
				Credentials: commoncfg.OAuth2Credentials{
					AuthMethod: commoncfg.OAuth2None,
				},
				MTLS: &commoncfg.MTLS{
					Cert: commoncfg.SourceRef{
						Source: commoncfg.FileSourceValue,
						File: commoncfg.CredentialFile{
							Path: "/nonexistent/cert.pem",
						},
					},
				},
			},
			clientID: "test-client",
			wantErr:  true,
			// Error will be about loading mTLS config
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Arrange
			builder := oauth2client.NewBuilder(tc.template)

			// Act
			client, err := builder(tc.clientID)

			// Assert
			if tc.wantErr {
				require.Error(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
				assert.Nil(t, client)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, client)
			}
		})
	}
}

func TestBuilder_SetsCorrectSourceRefProperties(t *testing.T) {
	t.Parallel()

	// Arrange - template uses EnvSourceValue for clientID
	template := commoncfg.OAuth2{
		Credentials: commoncfg.OAuth2Credentials{
			ClientID: commoncfg.SourceRef{
				Source: commoncfg.EnvSourceValue, // Different source type
				Env:    "SOME_ENV_VAR",
			},
			AuthMethod: commoncfg.OAuth2ClientSecretPost,
			ClientSecret: &commoncfg.SourceRef{
				Source: commoncfg.EmbeddedSourceValue,
				Value:  "test-secret",
			},
		},
	}
	builder := oauth2client.NewBuilder(template)

	// The builder should override the Source to EmbeddedSourceValue
	// and use the provided clientID as the Value
	expectedClientID := "my-embedded-client-id"

	// Capture the clientID that gets injected
	var capturedClientID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		q, _ := url.ParseQuery(string(body))
		capturedClientID = q.Get("client_id")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Act
	client, err := builder(expectedClientID)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL, strings.NewReader("grant_type=client_credentials"))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Assert
	assert.Equal(t, expectedClientID, capturedClientID)
}

func TestBuilder_SuccessWithDifferentAuthMethods(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		template commoncfg.OAuth2
		clientID string
	}{
		{
			name: "client_secret_post",
			template: commoncfg.OAuth2{
				Credentials: commoncfg.OAuth2Credentials{
					AuthMethod: commoncfg.OAuth2ClientSecretPost,
					ClientSecret: &commoncfg.SourceRef{
						Source: commoncfg.EmbeddedSourceValue,
						Value:  "secret",
					},
				},
			},
			clientID: "post-client",
		},
		{
			name: "client_secret_basic",
			template: commoncfg.OAuth2{
				Credentials: commoncfg.OAuth2Credentials{
					AuthMethod: commoncfg.OAuth2ClientSecretBasic,
					ClientSecret: &commoncfg.SourceRef{
						Source: commoncfg.EmbeddedSourceValue,
						Value:  "secret",
					},
				},
			},
			clientID: "basic-client",
		},
		{
			name: "client_secret_jwt",
			template: commoncfg.OAuth2{
				Credentials: commoncfg.OAuth2Credentials{
					AuthMethod: commoncfg.OAuth2ClientSecretJWT,
					ClientSecret: &commoncfg.SourceRef{
						Source: commoncfg.EmbeddedSourceValue,
						Value:  "secret",
					},
				},
				URL: &commoncfg.SourceRef{
					Source: commoncfg.EmbeddedSourceValue,
					Value:  "https://example.com/token",
				},
			},
			clientID: "jwt-client",
		},
		{
			name: "oauth2_none_pkce",
			template: commoncfg.OAuth2{
				Credentials: commoncfg.OAuth2Credentials{
					AuthMethod: commoncfg.OAuth2None,
				},
			},
			clientID: "pkce-client",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			builder := oauth2client.NewBuilder(tc.template)
			client, err := builder(tc.clientID)

			require.NoError(t, err)
			assert.NotNil(t, client)
		})
	}
}
