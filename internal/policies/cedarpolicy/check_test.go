package cedarpolicy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/extauthz/internal/policies/cedarpolicy"
)

func TestCheckWithPath(t *testing.T) {
	t.Run("no panic with nil options", func(t *testing.T) {
		engine, err := cedarpolicy.NewEngine(nil)
		assert.NoError(t, err)
		assert.NotPanics(t, func() {
			//nolint:errcheck
			engine.Check(nil)
		})
	})

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
		cntxt       map[string]string
		wantError   bool
		wantAllowed bool
	}{
		{
			name:  "zero values",
			cntxt: map[string]string{},
		}, {
			name:    "permit if me accesses GET on my stuff",
			subject: "me!t1",
			action:  "GET",
			cntxt: map[string]string{
				"type":   "jwt",
				"host":   "our.service.com",
				"path":   "/my/stuff/abc",
				"issuer": "https://127.0.0.1:1234",
			},
			wantAllowed: true,
		}, {
			name:    "permit if you accesses GET on your stuff",
			subject: "you!t1",
			action:  "GET",
			cntxt: map[string]string{
				"type":   "jwt",
				"host":   "our.service.com",
				"path":   "/your/stuff/bla",
				"issuer": "https://127.0.0.1:1234",
			},
			wantAllowed: true,
		}, {
			name:    "forbid if me accesses GET on your stuff",
			subject: "me!t1",
			action:  "GET",
			cntxt: map[string]string{
				"type":   "jwt",
				"host":   "our.service.com",
				"path":   "/your/stuff/bla",
				"issuer": "https://127.0.0.1:1234",
			},
			wantAllowed: false,
		}, {
			name:    "forbid if you accesses GET on my stuff",
			subject: "you!t1",
			action:  "GET",
			cntxt: map[string]string{
				"type":   "jwt",
				"host":   "our.service.com",
				"path":   "/my/stuff/abc",
				"issuer": "https://127.0.0.1:1234",
			},
			wantAllowed: false,
		},
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			engine, err := cedarpolicy.NewEngine(cedarpolicy.WithPath(tmpdir))
			if err != nil {
				t.Fatalf("failed to create engine: %s", err)
			}

			// Act
			allowed, reason, err := engine.Check(
				cedarpolicy.WithSubject(tc.subject),
				cedarpolicy.WithAction(tc.action),
				cedarpolicy.WithContextData(tc.cntxt),
			)
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
