//go:build helmtests

package main_test

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

func TestService(t *testing.T) {
	ctx := t.Context()
	tests := []struct {
		name     string
		values   string
		expected []string
	}{
		{
			name:   "default values",
			values: "",
			expected: []string{
				"kind: Service",
				"name: " + appName,
				"namespace: default",
				"type: ClusterIP",
				"port: 9092",
				"targetPort: 9092",
				"port: 8080",
				"targetPort: 8080",
			},
		},
		{
			name:   "custom values",
			values: "--set service.type=NodePort --set service.ports[0].port=9093 --set service.ports[0].targetPort=9093 --set service.ports[1].port=8081 --set service.ports[1].targetPort=8081 --namespace foo",
			expected: []string{
				"kind: Service",
				"name: " + appName,
				"namespace: foo",
				"type: NodePort",
				"port: 9093",
				"targetPort: 9093",
				"port: 8081",
				"targetPort: 8081",
			},
		},
		{
			name:   "LoadBalancer type",
			values: "--set service.type=LoadBalancer",
			expected: []string{
				"type: LoadBalancer",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"template", appName, path, "-s", "templates/service.yaml",
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
		})
	}
}
