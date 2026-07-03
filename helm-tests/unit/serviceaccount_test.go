//go:build helmtests

package main_test

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

func TestServiceAccount(t *testing.T) {
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
				"kind: ServiceAccount",
				"name: " + appName,
				"namespace: default",
				"automountServiceAccountToken: true",
			},
		},
		{
			name:   "custom values - automount disabled",
			values: "--set serviceAccount.automount=false --namespace foo",
			expected: []string{
				"kind: ServiceAccount",
				"name: " + appName,
				"namespace: foo",
				"automountServiceAccountToken: false",
			},
		},
		{
			name:   "custom service account name",
			values: "--set serviceAccount.name=my-custom-sa",
			expected: []string{
				"name: my-custom-sa",
			},
		},
		{
			name:   "with annotations",
			values: "--set serviceAccount.annotations.iam\\.gke\\.io/gcp-service-account=mysa@myproject.iam.gserviceaccount.com",
			expected: []string{
				"annotations:",
				"iam.gke.io/gcp-service-account: mysa@myproject.iam.gserviceaccount.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"template", appName, path, "-s", "templates/serviceaccount.yaml",
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
