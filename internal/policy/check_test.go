package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/openkcm/extauthz/internal/policy"
)

func TestCheckWithPath(t *testing.T) {
	// create policy files
	tmpdir := t.TempDir()
	for name, content := range policies {
		path := filepath.Join(tmpdir, name)

		err := os.WriteFile(path, []byte(content), 0644)
		if err != nil {
			t.Fatalf("failed to create file: %s", err)
		}
	}

	// create the test cases
	tests := []struct {
		name        string
		subject     string
		action      string
		route       string
		cntxt       map[string]string
		wantError   bool
		wantAllowed bool
	}{
		{
			name: "zero values",
		}, {
			name:        "permit if me accesses GET on mine",
			subject:     "me",
			action:      "GET",
			route:       "my.service.com/mine",
			cntxt:       map[string]string{"route": "my.service.com/mine"},
			wantAllowed: true,
		}, {
			name:        "permit if you accesses GET on yours",
			subject:     "you",
			action:      "GET",
			route:       "my.service.com/yours",
			cntxt:       map[string]string{"route": "my.service.com/yours"},
			wantAllowed: true,
		}, {
			name:        "forbid if me accesses GET on yours",
			subject:     "me",
			action:      "GET",
			route:       "my.service.com/yours",
			cntxt:       map[string]string{"route": "my.service.com/yours"},
			wantAllowed: false,
		}, {
			name:        "forbid if you accesses GET on mine",
			subject:     "you",
			action:      "GET",
			route:       "my.service.com/mine",
			cntxt:       map[string]string{"route": "my.service.com/mine"},
			wantAllowed: false,
		},
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			engine, err := policy.NewEngine(policy.WithPath(tmpdir))
			if err != nil {
				t.Fatalf("failed to create engine: %s", err)
			}

			// Act
			allowed, reason, err := engine.Check(tc.subject, tc.action, tc.route, tc.cntxt)
			t.Logf("reason: %s", reason)

			// Assert
			if tc.wantError {
				if err == nil {
					t.Error("expected error, but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %s", err)
				} else {
					if allowed != tc.wantAllowed {
						t.Errorf("expected decision %v, but got %v", tc.wantAllowed, allowed)
					}
				}
			}
		})
	}
}
