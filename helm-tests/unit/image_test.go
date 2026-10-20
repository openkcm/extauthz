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
)

// chartAppVersion returns the appVersion of the chart, the default image tag.
func chartAppVersion(t *testing.T) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(path, "Chart.yaml"))
	if err != nil {
		t.Fatalf("reading Chart.yaml: %v", err)
	}

	var chart struct {
		AppVersion string `yaml:"appVersion"`
	}

	err = yaml.Unmarshal(data, &chart)
	if err != nil {
		t.Fatalf("parsing Chart.yaml: %v", err)
	}

	if chart.AppVersion == "" {
		t.Fatal("Chart.yaml has no appVersion")
	}

	return chart.AppVersion
}

// TestDeploymentImage renders the Deployment without image.tag, which the other tests set.
func TestDeploymentImage(t *testing.T) {
	ctx := t.Context()
	appVersion := chartAppVersion(t)
	image := "ghcr.io/openkcm/extauthz/images/extauthz"
	digest := "sha256:" + strings.Repeat("0e07", 16)

	tests := []struct {
		name       string
		values     string
		expected   []string
		unexpected []string
	}{
		{
			name:   "default tag is the chart's appVersion",
			values: "",
			expected: []string{
				`image: "` + image + ":" + appVersion + `"`,
				`app.kubernetes.io/version: "` + appVersion + `"`,
			},
		},
		{
			name:   "digest takes precedence over the tag",
			values: "--set image.tag=v9.9.9 --set image.digest=" + digest,
			expected: []string{
				`image: "` + image + "@" + digest + `"`,
			},
			unexpected: []string{
				image + ":v9.9.9",
				image + ":" + appVersion,
			},
		},
		{
			name:   "digest without a tag",
			values: "--set image.digest=" + digest,
			expected: []string{
				`image: "` + image + "@" + digest + `"`,
			},
			unexpected: []string{
				image + ":" + appVersion,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"template", appName, path, "-s", "templates/deployment.yaml"}
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
