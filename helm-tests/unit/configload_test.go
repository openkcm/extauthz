//go:build helmtests

package main_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/openkcm/common-sdk/pkg/commoncfg"

	"github.com/openkcm/extauthz/internal/config"
)

// TestConfigLoad renders config.yaml and loads it with ExtAuthZ's configuration loader, the
// same call as in cmd/extauthz/main.go. The loader rejects unknown keys, so a key that the
// chart writes but ExtAuthZ does not know fails the test. The testdata files contain every
// example that values.yaml documents under `config`; alternatives that exclude each other
// are in separate files.
func TestConfigLoad(t *testing.T) {
	ctx := t.Context()
	tests := []struct {
		name    string
		values  []string
		wantErr string
		check   func(t *testing.T, cfg *config.Config)
	}{
		{
			name: "default values",
			check: func(t *testing.T, cfg *config.Config) {
				t.Helper()
				if cfg.GRPCServer.Address != ":9092" || cfg.Status.Address != ":8080" {
					t.Errorf("unexpected listen addresses: gRPC %q, status %q", cfg.GRPCServer.Address, cfg.Status.Address)
				}
			},
		},
		{
			name:   "every documented optional section",
			values: []string{"-f", "testdata/all-config-values.yaml"},
			check:  checkAllConfigValues,
		},
		{
			name:   "documented alternatives, part 1",
			values: []string{"-f", "testdata/config-alternatives-1.yaml"},
			check:  checkConfigAlternatives1,
		},
		{
			name:   "documented alternatives, part 2",
			values: []string{"-f", "testdata/config-alternatives-2.yaml"},
			check:  checkConfigAlternatives2,
		},
		{
			name:   "documented alternatives, part 3",
			values: []string{"-f", "testdata/config-alternatives-3.yaml"},
			check:  checkConfigAlternatives3,
		},
		{
			name:   "documented alternatives, part 4",
			values: []string{"-f", "testdata/config-alternatives-4.yaml"},
			check: func(t *testing.T, cfg *config.Config) {
				t.Helper()
				if cfg.JWT.OAuth2.Credentials.AuthMethod != commoncfg.OAuth2None {
					t.Errorf("jwt.oauth2 not loaded: %+v", cfg.JWT.OAuth2)
				}
			},
		},
		{
			// Proves that the check is strict: a misspelled key fails to load.
			name:    "unknown key inside a section is rejected",
			values:  []string{"--set", "config.logger.levl=info"},
			wantErr: "invalid keys",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"template", appName, path, "-s", "templates/configmap.yaml"}, tt.values...)

			cmd := exec.CommandContext(ctx, "helm", args...)
			var out, stderr bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &stderr

			err := cmd.Run()
			if err != nil {
				t.Fatalf("helm template failed: %v\nOutput: %s%s", err, out.String(), stderr.String())
			}

			var configMap struct {
				Data map[string]string `yaml:"data"`
			}

			err = yaml.Unmarshal(out.Bytes(), &configMap)
			if err != nil {
				t.Fatalf("parsing the ConfigMap: %v\nOutput: %s", err, out.String())
			}

			configYAML, ok := configMap.Data["config.yaml"]
			if !ok {
				t.Fatalf("the ConfigMap has no config.yaml\nOutput: %s", out.String())
			}

			dir := t.TempDir()

			err = os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(configYAML), 0o600)
			if err != nil {
				t.Fatalf("writing config.yaml: %v", err)
			}

			// As in run() of cmd/extauthz/main.go, with the rendered file as the only path.
			cfg := &config.Config{}
			err = commoncfg.LoadConfig(cfg, map[string]any{}, dir)

			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected an error containing %q, got %v\nconfig.yaml:\n%s", tt.wantErr, err, configYAML)
				}

				return
			}

			if err != nil {
				t.Fatalf("ExtAuthZ cannot load the rendered configuration: %v\nconfig.yaml:\n%s", err, configYAML)
			}

			tt.check(t, cfg)
		})
	}
}

// checkAllConfigValues checks samples of testdata/all-config-values.yaml.
func checkAllConfigValues(t *testing.T, cfg *config.Config) {
	t.Helper()
	if cfg.Application.Name != "extauthz-eu10" || cfg.Application.Environment != "staging" {
		t.Errorf("application not loaded: %+v", cfg.Application)
	}
	if cfg.Logger.Formatter.Time.Type != commoncfg.PatternTimeLogger ||
		len(cfg.Logger.Formatter.Fields.Masking.PII) != 1 ||
		cfg.Logger.Formatter.Fields.Masking.Other["payload"] == "" {
		t.Errorf("logger.formatter not loaded: %+v", cfg.Logger.Formatter)
	}
	if cfg.GRPCServer.Client.Pool.IdleTimeout == 0 || cfg.GRPCServer.Attributes.Time == 0 {
		t.Errorf("grpcServer settings not loaded: %+v", cfg.GRPCServer)
	}
	checkAllConfigValuesJWT(t, cfg)
	smRef := cfg.SessionManager.SecretRef
	if smRef == nil || smRef.Type != commoncfg.MTLSSecretType || smRef.MTLS.Attributes == nil ||
		smRef.MTLS.Attributes.ServerName == "" {
		t.Errorf("sessionManager.secretRef not loaded: %+v", smRef)
	}
	if cfg.CSRFSecret.Source != commoncfg.FileSourceValue || cfg.CSRFSecret.File.Format != commoncfg.BinaryFileFormat {
		t.Errorf("csrfSecret not loaded: %+v", cfg.CSRFSecret)
	}
	if cfg.Valkey.User.Value != "extauthz" || cfg.Valkey.Password.File.Path == "" ||
		cfg.Valkey.MasterSet != "mymaster" || cfg.Valkey.SecretRef.Type != commoncfg.MTLSSecretType {
		t.Errorf("valkey not loaded: %+v", cfg.Valkey)
	}
	if cfg.Audit.Endpoint == "" || cfg.Audit.HTTPClient.MTLS == nil || cfg.Audit.AdditionalProperties == "" {
		t.Errorf("audit not loaded: %+v", cfg.Audit)
	}
	if !cfg.Telemetry.Metrics.Prometheus.Enabled ||
		cfg.Telemetry.Traces.SecretRef.Type != commoncfg.MTLSSecretType ||
		cfg.Telemetry.Logs.SecretRef.Type != commoncfg.BasicSecretType {
		t.Errorf("telemetry not loaded: %+v", cfg.Telemetry)
	}
}

// checkAllConfigValuesJWT checks the jwt section of testdata/all-config-values.yaml.
func checkAllConfigValuesJWT(t *testing.T, cfg *config.Config) {
	t.Helper()
	if len(cfg.JWT.Providers) != 2 || cfg.JWT.Providers[1].JwksURI == "" ||
		!cfg.JWT.Providers[1].DisableTokenIntrospection {
		t.Errorf("jwt.providers not loaded: %+v", cfg.JWT.Providers)
	}
	if cfg.JWT.HTTPClient.BasicAuth == nil || cfg.JWT.HTTPClient.BasicAuth.Password.File.Path == "" {
		t.Errorf("jwt.httpClient.basicAuth not loaded: %+v", cfg.JWT.HTTPClient)
	}
	if cfg.JWT.OAuth2.Credentials.AuthMethod != commoncfg.OAuth2ClientSecretPost ||
		cfg.JWT.OAuth2.Credentials.ClientSecret == nil {
		t.Errorf("jwt.oauth2 not loaded: %+v", cfg.JWT.OAuth2)
	}
}

// checkConfigAlternatives1 checks samples of testdata/config-alternatives-1.yaml.
func checkConfigAlternatives1(t *testing.T, cfg *config.Config) {
	t.Helper()
	if cfg.Logger.Formatter.Time.Type != commoncfg.UnixTimeLogger || cfg.Logger.Formatter.Fields.Message != "msg" {
		t.Errorf("logger defaults not loaded: %+v", cfg.Logger)
	}
	if cfg.JWT.HTTPClient.APIToken == nil || cfg.JWT.HTTPClient.APIToken.Env != "IDP_API_TOKEN" {
		t.Errorf("jwt.httpClient.apiToken not loaded: %+v", cfg.JWT.HTTPClient)
	}
	if cfg.JWT.OAuth2.Credentials.AuthMethod != commoncfg.OAuth2ClientSecretJWT || cfg.JWT.OAuth2.URL == nil {
		t.Errorf("jwt.oauth2 not loaded: %+v", cfg.JWT.OAuth2)
	}
	if cfg.SessionManager.SecretRef == nil || cfg.SessionManager.SecretRef.Type != commoncfg.InsecureSecretType {
		t.Errorf("sessionManager.secretRef not loaded: %+v", cfg.SessionManager.SecretRef)
	}
	if cfg.CSRFSecret.Source != commoncfg.EnvSourceValue || cfg.CSRFSecret.Env != "CSRF_SECRET" {
		t.Errorf("csrfSecret not loaded: %+v", cfg.CSRFSecret)
	}
	if cfg.Audit.HTTPClient.APIToken == nil || cfg.Audit.HTTPClient.APIToken.Env != "AUDIT_API_TOKEN" {
		t.Errorf("audit.httpClient.apiToken not loaded: %+v", cfg.Audit.HTTPClient)
	}
	if cfg.Valkey.Address.Env != "VALKEY_ADDRESS" || cfg.Valkey.Password.Env != "VALKEY_PASSWORD" {
		t.Errorf("valkey not loaded: %+v", cfg.Valkey)
	}
	tel := cfg.Telemetry
	if tel.Traces.Protocol != commoncfg.HTTPProtocol || tel.Metrics.URL != "/v1/metrics" ||
		tel.Logs.SecretRef.Type != commoncfg.ApiTokenSecretType || !tel.DynatraceOneAgent {
		t.Errorf("telemetry not loaded: %+v", tel)
	}
}

// checkConfigAlternatives2 checks samples of testdata/config-alternatives-2.yaml.
func checkConfigAlternatives2(t *testing.T, cfg *config.Config) {
	t.Helper()
	oauth2Auth := cfg.JWT.HTTPClient.OAuth2Auth
	if oauth2Auth == nil || oauth2Auth.Credentials.ClientID.Value != "extauthz" ||
		oauth2Auth.Credentials.AuthMethod != commoncfg.OAuth2ClientSecretBasic {
		t.Errorf("jwt.httpClient.oauth2Auth not loaded: %+v", oauth2Auth)
	}
	creds := cfg.JWT.OAuth2.Credentials
	if creds.AuthMethod != commoncfg.OAuth2PrivateKeyJWT || creds.ClientAssertion == nil ||
		creds.ClientAssertionType == nil {
		t.Errorf("jwt.oauth2 not loaded: %+v", creds)
	}
	if cfg.CSRFSecret.File.Format != commoncfg.JSONFileFormat || cfg.CSRFSecret.File.JSONPath == "" {
		t.Errorf("csrfSecret not loaded: %+v", cfg.CSRFSecret)
	}
	if cfg.Valkey.Address.File.Path == "" || cfg.Valkey.User.File.JSONPath != "$.user" {
		t.Errorf("valkey not loaded: %+v", cfg.Valkey)
	}
}

// checkConfigAlternatives3 checks samples of testdata/config-alternatives-3.yaml.
func checkConfigAlternatives3(t *testing.T, cfg *config.Config) {
	t.Helper()
	httpClient := cfg.JWT.HTTPClient
	if httpClient.MTLS == nil || httpClient.TransportAttributes == nil ||
		httpClient.TransportAttributes.MaxConnsPerHost != 50 {
		t.Errorf("jwt.httpClient not loaded: %+v", httpClient)
	}
	if cfg.JWT.OAuth2.MTLS == nil || cfg.JWT.OAuth2.MTLS.CertKey.File.Path == "" {
		t.Errorf("jwt.oauth2.mtls not loaded: %+v", cfg.JWT.OAuth2)
	}
}
