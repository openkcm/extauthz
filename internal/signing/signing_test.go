package signing_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/openkcm/extauthz/internal/signing"
)

func TestFromFile(t *testing.T) {
	// Arrange
	keyID := "testkey"
	tmpdir := t.TempDir()
	// Generate a private key and write it to a file
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	privateKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	)

	keyFilePath := filepath.Join(tmpdir, keyID+".pem")

	err = os.WriteFile(keyFilePath, privateKeyPEM, 0644)
	if err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	// Create a file referencing the valid key ID
	keyIDFilePathValid := filepath.Join(tmpdir, "valid_keyID.txt")

	err = os.WriteFile(keyIDFilePathValid, []byte(keyID), 0644)
	if err != nil {
		t.Fatalf("failed to write valid key ID file: %v", err)
	}
	// Create another file referencing an invalid key ID
	keyIDFilePathInvalid := filepath.Join(tmpdir, "invalid_keyID.txt")

	err = os.WriteFile(keyIDFilePathInvalid, []byte("foo"), 0644)
	if err != nil {
		t.Fatalf("failed to write invalid key ID file: %v", err)
	}

	// create the test cases
	tests := []struct {
		name      string
		keyIDFile string
		wantError bool
	}{
		{
			name:      "zero values",
			wantError: true,
		}, {
			name:      "invalid key ID file",
			keyIDFile: keyIDFilePathInvalid,
			wantError: true,
		}, {
			name:      "valid key ID file",
			keyIDFile: keyIDFilePathValid,
			wantError: false,
		},
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange

			// Act
			key, err := signing.FromFile(tc.keyIDFile)

			// Assert
			if tc.wantError {
				if err == nil {
					t.Error("expected error, but got nil")
				}

				if key != nil {
					t.Errorf("expected nil key, but got: %v", key)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %s", err)
				}
			}
		})
	}
}

func TestGenerateKey(t *testing.T) {
	key, err := signing.GenerateKey()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if key.ID == "" {
		t.Fatal("expected non-empty key ID")
	}

	if key.Private == nil {
		t.Fatal("expected non-nil private key")
	}

	if len(key.Private.D.Bytes()) == 0 {
		t.Fatal("expected non-empty private key D value")
	}
}
