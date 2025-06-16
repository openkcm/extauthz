package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/openkcm/extauthz/internal/policy"
)

func TestWithFile(t *testing.T) {
	// Arrange
	tmpdir := t.TempDir()
	path := filepath.Join(tmpdir, policy1)

	// create the test cases
	tests := []struct {
		name      string
		policy    string
		path      string
		wantError bool
	}{
		{
			name:      "zero values",
			wantError: true,
		}, {
			name:      "invalid file",
			policy:    "",
			path:      "/does/not/exist",
			wantError: true,
		}, {
			name:      "invalid policy",
			policy:    "invalid policy",
			path:      path,
			wantError: true,
		}, {
			name:      "valid policy",
			policy:    policies[policy1],
			path:      path,
			wantError: false,
		},
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			err := os.WriteFile(path, []byte(tc.policy), 0644)
			if err != nil {
				t.Fatalf("failed to create file: %s", err)
			}

			// Act
			_, err = policy.NewEngine(policy.WithFile(tc.path))

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

func TestWithBytes(t *testing.T) {
	// create the test cases
	tests := []struct {
		name      string
		policy    string
		wantError bool
	}{
		{
			name: "zero values",
		}, {
			name:      "invalid policy",
			policy:    "invalid policy",
			wantError: true,
		}, {
			name:      "valid policy",
			policy:    policies[policy1],
			wantError: false,
		},
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			_, err := policy.NewEngine(policy.WithBytes("p0", []byte(tc.policy)))

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
