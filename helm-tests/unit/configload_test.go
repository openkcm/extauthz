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
// chart writes but ExtAuthZ does not know fails the test.
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
			check: func(t *testing.T, cfg *config.Config) {
				t.Helper()
				if cfg.SessionManager.SecretRef == nil || cfg.SessionManager.SecretRef.Type != commoncfg.MTLSSecretType {
					t.Errorf("sessionManager.secretRef not loaded: %+v", cfg.SessionManager.SecretRef)
				}
				if cfg.Valkey.User.Value != "extauthz" || cfg.Valkey.Password.File.Path == "" {
					t.Errorf("valkey user or password not loaded: %+v", cfg.Valkey)
				}
				if cfg.Audit.Endpoint == "" || !cfg.Telemetry.Metrics.Prometheus.Enabled {
					t.Errorf("audit or telemetry not loaded: %+v %+v", cfg.Audit, cfg.Telemetry)
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
