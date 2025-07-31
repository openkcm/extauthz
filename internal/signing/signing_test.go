package signing_test

import (
	"testing"
	"time"

	"github.com/openkcm/extauthz/internal/signing"
)

func TestAll(t *testing.T) {
	// create the test cases
	tests := []struct {
		name      string
		interval  time.Duration
		wantError bool
	}{
		{
			name:      "zero values",
			wantError: true,
		}, {
			name:      "zero interval",
			interval:  0,
			wantError: true,
		}, {
			name:      "short interval",
			interval:  time.Millisecond,
			wantError: false,
		},
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange

			// Act
			key, err := signing.NewKey(t.Context(), signing.WithRefreshInterval(tc.interval))

			// Assert
			if tc.wantError {
				if err == nil {
					t.Error("expected error, but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %s", err)
				} else {
					_, _, err := key.Private()
					if err != nil {
						t.Errorf("unexpected error getting private key: %s", err)
					}

					_, _, err = key.PublicPEM()
					if err != nil {
						t.Errorf("unexpected error getting public key: %s", err)
					}
				}
			}
		})
	}
}
