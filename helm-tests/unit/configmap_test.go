//go:build helmtests

package main_test

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

func TestConfigMap(t *testing.T) {
	ctx := t.Context()
	tests := []struct {
		name       string
		values     string
		expected   []string
		unexpected []string
	}{
		{
			name:   "default values omit optional audit and valkey blocks",
			values: "",
			expected: []string{
				"kind: ConfigMap",
				"name: " + appName + "-config",
				"config.yaml:",
				"cedar:",
				"clientData:",
			},
			// audit / valkey are optional and commented out by default, so the
			// rendered config must not contain them.
			unexpected: []string{
				"\n    audit:",
				"\n    valkey:",
			},
		},
		{
			name: "audit block is rendered when configured",
			values: "--set config.audit.endpoint=http://als:4317/v1/logs " +
				"--set config.audit.httpClient.timeout=10s",
			expected: []string{
				"audit:",
				"endpoint: http://als:4317/v1/logs",
				"timeout: 10s",
			},
		},
		{
			name: "valkey rate detection block is rendered when configured",
			values: "--set config.valkey.address.value=valkey:6379 " +
				"--set config.valkey.prefix=extauthz " +
				"--set config.valkey.secretRef.type=insecure " +
				"--set config.valkey.rateDetection.enabled=true " +
				"--set config.valkey.rateDetection.threshold=50 " +
				"--set config.valkey.rateDetection.window=1m " +
				"--set config.valkey.rateDetection.cooldown=1m " +
				"--set config.valkey.rateDetection.countUnknown=false " +
				"--set config.valkey.rateDetection.queueSize=1024 " +
				"--set config.valkey.rateDetection.workers=4",
			expected: []string{
				"valkey:",
				"value: valkey:6379",
				"prefix: extauthz",
				"rateDetection:",
				"enabled: true",
				"threshold: 50",
				"window: 1m",
				"cooldown: 1m",
				"queueSize: 1024",
				"workers: 4",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"template", appName, path, "-s", "templates/configmap.yaml",
				"--set", "image.tag=foo",
			}
			if tt.values != "" {
				args = append(args, strings.Split(tt.values, " ")...)
			}

			cmd := exec.CommandContext(ctx, "helm", args...)
			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &out

			err := cmd.Run()
			if err != nil {
				t.Fatalf("helm template failed: %v\nOutput: %s", err, out.String())
			}

			output := out.String()
			for _, expected := range tt.expected {
				if !strings.Contains(output, expected) {
					t.Errorf("expected output to contain %q, but it didn't.\nOutput: %s", expected, output)
				}
			}
			for _, unexpected := range tt.unexpected {
				if strings.Contains(output, unexpected) {
					t.Errorf("expected output NOT to contain %q, but it did.\nOutput: %s", unexpected, output)
				}
			}
		})
	}
}
