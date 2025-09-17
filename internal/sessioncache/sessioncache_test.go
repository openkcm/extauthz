package sessioncache_test

import (
	"testing"

	"github.com/openkcm/extauthz/internal/extauthz"
	"github.com/openkcm/extauthz/internal/sessioncache"
)

func TestGet(t *testing.T) {
	// Arrange
	sessionCache, err := sessioncache.New()
	if err != nil {
		t.Fatalf("failed to create session cache: %s", err)
	}

	// create the test cases
	tests := []struct {
		name        string
		sessionID   string
		wantFound   bool
		wantSession *extauthz.Session
	}{
		{
			name: "zero values",
		},
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			_, found := sessionCache.Get(t.Context(), tc.sessionID)

			// Assert
			if found != tc.wantFound {
				t.Errorf("expected found: %v, got: %v", tc.wantFound, found)
			}
		})
	}
}
