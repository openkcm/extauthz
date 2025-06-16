//go:build integration

package integration_test

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestConfig(t *testing.T) {
	// create the test cases
	tests := []struct {
		name            string
		config          string
		trustedSubjects string
		wantError       bool
	}{
		{
			name:      "zero values",
			wantError: true,
		}, {
			name:      "invalid config, unknown keys",
			config:    `foo: bar`,
			wantError: true,
		}, {
			name:      "valid config, but no trustedSubjects.yaml",
			config:    validConfig,
			wantError: true,
		}, {
			name:            "valid config, but invalid trustedSubjects.yaml",
			config:          validConfig,
			trustedSubjects: `%`,
			wantError:       true,
		},
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange

			// write config.yaml
			if tc.config != "" {
				file := "./config.yaml"
				err := os.WriteFile(file, []byte(tc.config), 0640)
				if err != nil {
					t.Errorf("could not write file: %v, got: %s", file, err)
				}
				defer os.Remove(file)
			}

			// write trustedSubjects.yaml
			if tc.trustedSubjects != "" {
				file := "./trustedSubjects.yaml"
				err := os.WriteFile(file, []byte(tc.trustedSubjects), 0640)
				if err != nil {
					t.Errorf("could not write file: %v, got: %s", file, err)
				}
				defer os.Remove(file)
			}

			// create the command with a timeout context
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "./"+binary)

			// Act
			_, err := cmd.CombinedOutput()

			// Assert
			if tc.wantError {
				if err == nil {
					t.Error("expected error, but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %s", err)
				}
			}
		})
	}
}
