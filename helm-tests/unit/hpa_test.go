//go:build helmtests

package main_test

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

func TestHorizontalPodAutoscaler(t *testing.T) {
	ctx := t.Context()
	tests := []struct {
		name     string
		values   string
		expected []string
	}{
		{
			name:   "default values",
			values: "--set hpa.enabled=true",
			expected: []string{
				"kind: HorizontalPodAutoscaler",
				"name: " + appName,
				"namespace: default",
				"minReplicas: 1",
				"maxReplicas: 100",
				"name: cpu",
				"averageUtilization: 80",
				"name: memory",
			},
		},
		{
			name:   "custom values",
			values: "--set hpa.enabled=true --set hpa.minReplicas=2 --set hpa.maxReplicas=5 --set hpa.targetCPUUtilizationPercentage=70 --set hpa.targetMemoryUtilizationPercentage=70 --namespace foo",
			expected: []string{
				"kind: HorizontalPodAutoscaler",
				"name: " + appName,
				"namespace: foo",
				"minReplicas: 2",
				"maxReplicas: 5",
				"name: cpu",
				"averageUtilization: 70",
				"name: memory",
			},
		},
		{
			name:     "HPA disabled by default",
			values:   "",
			expected: []string{
				// When HPA is disabled, the template should not render
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"template", appName, path, "-s", "templates/hpa.yaml",
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
			output := out.String()

			// For "HPA disabled by default" case, we expect an error or empty output
			if tt.name == "HPA disabled by default" {
				if err == nil && strings.Contains(output, "kind: HorizontalPodAutoscaler") {
					t.Errorf("expected HPA to not be rendered when disabled, but got output:\n%s", output)
				}
				return
			}

			if err != nil {
				t.Fatalf("helm template failed: %v\nOutput: %s", err, output)
			}

			for _, expected := range tt.expected {
				if !strings.Contains(output, expected) {
					t.Errorf("expected output to contain %q, but it didn't.\nOutput: %s", expected, output)
				}
			}
		})
	}
}
