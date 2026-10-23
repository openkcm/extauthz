//go:build helmtests

package main_test

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

func TestNetworkPolicy(t *testing.T) {
	ctx := t.Context()
	tests := []struct {
		name       string
		values     string
		expected   []string
		unexpected []string
	}{
		{
			name:       "disabled by default",
			values:     "",
			unexpected: []string{"kind: NetworkPolicy"},
		},
		{
			name: "only the listed peers may call the gRPC API",
			values: "--set networkPolicy.enabled=true " +
				"--set networkPolicy.grpc.from[0].podSelector.matchLabels.app\\.kubernetes\\.io/name=envoy",
			expected: []string{
				"kind: NetworkPolicy",
				"name: " + appName,
				"- Ingress",
				"port: grpc",
				"app.kubernetes.io/name: envoy",
			},
			// No status peers are configured, so no rule for the status port.
			unexpected: []string{
				"port: http-status",
			},
		},
		{
			name: "status port rule for a metrics collector",
			values: "--set networkPolicy.enabled=true " +
				"--set networkPolicy.status.from[0].namespaceSelector.matchLabels.kubernetes\\.io/metadata\\.name=monitoring",
			expected: []string{
				"port: http-status",
				"kubernetes.io/metadata.name: monitoring",
			},
			unexpected: []string{
				"port: grpc",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"template", appName, path, "--set", "image.tag=foo"}
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

			// Only look at the NetworkPolicy document.
			output := ""
			for doc := range strings.SplitSeq(out.String(), "\n---\n") {
				if strings.Contains(doc, "kind: NetworkPolicy") {
					output = doc
				}
			}
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
