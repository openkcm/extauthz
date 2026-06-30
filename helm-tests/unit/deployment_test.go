//go:build helmtests

package main_test

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

func TestDeployment(t *testing.T) {
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
				"kind: Deployment",
				"name: " + appName,
				"app.kubernetes.io/name: " + appName,
				"namespace: default",
				"name: registry-access",
				"serviceAccountName: " + appName,
			},
		},
		{
			name:   "custom values with HPA",
			values: "--set hpa.enabled=true --set hpa.minReplicas=3 --set imagePullSecrets[0].name=my-registry-access --set serviceAccount.name=my-extauthz",
			expected: []string{
				"kind: Deployment",
				"name: " + appName,
				"namespace: default",
				"replicas: 3",
				"name: my-registry-access",
				"serviceAccountName: my-extauthz",
			},
		},
		{
			name:   "extraContainers",
			values: "--set extraContainers[0].name=foo --set extraContainers[0].image=bar",
			expected: []string{
				"name: foo",
				"image: bar",
			},
		},
		{
			name:   "custom namespace",
			values: "--namespace mynamespace",
			expected: []string{
				"namespace: mynamespace",
			},
		},
		{
			name:   "custom replica count via hpa.minReplicas",
			values: "--set hpa.enabled=true --set hpa.minReplicas=5",
			expected: []string{
				"replicas: 5",
			},
		},
		{
			name:   "custom image",
			values: "--set image.registry=docker.io --set image.repository=myorg/extauthz",
			expected: []string{
				`image: "docker.io/myorg/extauthz:foo"`,
			},
		},
		{
			name:   "with resources",
			values: "--set resources.limits.cpu=1000m --set resources.limits.memory=512Mi --set resources.requests.cpu=100m --set resources.requests.memory=128Mi",
			expected: []string{
				"resources:",
				"limits:",
				"cpu: 1000m",
				"memory: 512Mi",
				"requests:",
				"cpu: 100m",
				"memory: 128Mi",
			},
		},
		{
			name:   "with pod annotations",
			values: "--set pod.annotations.prometheus\\.io/scrape=true --set pod.annotations.prometheus\\.io/port=8080",
			expected: []string{
				"annotations:",
				"prometheus.io/port: 8080",
				"prometheus.io/scrape: true",
			},
		},
		{
			name:   "with nodeSelector",
			values: "--set pod.nodeSelector.disktype=ssd --set pod.nodeSelector.zone=us-west",
			expected: []string{
				"nodeSelector:",
				"disktype: ssd",
				"zone: us-west",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"template", appName, path, "-s", "templates/deployment.yaml",
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
