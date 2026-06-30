//go:build helmtests

package main_test

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

func TestPodDisruptionBudget(t *testing.T) {
	ctx := t.Context()
	tests := []struct {
		name      string
		values    string
		expected  []string
		wantError bool
	}{
		{
			name:   "default values",
			values: "--set pod.disruptionBudget.enabled=true",
			expected: []string{
				"kind: PodDisruptionBudget",
				"name: " + appName,
				"namespace: default",
				"minAvailable: 1",
			},
		},
		{
			name:   "custom minAvailable",
			values: "--set pod.disruptionBudget.enabled=true --set pod.disruptionBudget.minAvailable=42 --namespace foo",
			expected: []string{
				"kind: PodDisruptionBudget",
				"name: " + appName,
				"namespace: foo",
				"minAvailable: 42",
			},
		},
		{
			name:   "custom maxUnavailable",
			values: "--set pod.disruptionBudget.enabled=true --set pod.disruptionBudget.maxUnavailable=42 --namespace foo",
			expected: []string{
				"kind: PodDisruptionBudget",
				"name: " + appName,
				"namespace: foo",
				"maxUnavailable: 42",
			},
		},
		{
			name:      "conflicting minAvailable + maxUnavailable",
			values:    "--set pod.disruptionBudget.enabled=true --set pod.disruptionBudget.minAvailable=41 --set pod.disruptionBudget.maxUnavailable=43",
			wantError: true,
		},
		{
			name:     "PDB disabled by default",
			values:   "",
			expected: []string{
				// When PDB is disabled, the template should not render
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"template", appName, path, "-s", "templates/pdb.yaml",
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

			// For error case
			if tt.wantError {
				if err == nil {
					t.Errorf("expected error but got none.\nOutput: %s", output)
				}
				return
			}

			// For "PDB disabled by default" case, we expect an error or empty output
			if tt.name == "PDB disabled by default" {
				if err == nil && strings.Contains(output, "kind: PodDisruptionBudget") {
					t.Errorf("expected PDB to not be rendered when disabled, but got output:\n%s", output)
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
