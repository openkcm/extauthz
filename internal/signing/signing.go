// Package signing handles the loading of signing keys from files.
// It expects a configuration file with the key ID and potentially
// several private keys in the same directory. The key ID in the
// configuration file is used to determine which private key to load.
//
// Example structure:
//   - ./keyID.txt
//     Content: "key1"
//   - ./key1.priv
//   - ./key2.priv
package signing

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Key struct {
	ID      string
	Private *rsa.PrivateKey
}

// FromFile loads a signing key as indicated in the given key ID file.
func FromFile(keyIDFilePath string) (*Key, error) {
	keyID, err := loadKeyID(keyIDFilePath)
	if err != nil {
		return nil, fmt.Errorf("could not load key ID: %w", err)
	}

	keyFilePath := filepath.Join(
		filepath.Dir(keyIDFilePath),
		keyID+".priv",
	)

	privateKey, err := loadPrivateKey(keyFilePath)
	if err != nil {
		return nil, fmt.Errorf("could not load private key: %w", err)
	}

	return &Key{
		ID:      keyID,
		Private: privateKey,
	}, nil
}

// GenerateKey is used in tests to generate a new signing key.
func GenerateKey() (*Key, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	return &Key{
		ID:      uuid.NewString(),
		Private: privateKey,
	}, nil
}

// loadKeyID reads and trims the key ID from the given file.
func loadKeyID(file string) (string, error) {
	fbytes, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("could not read file: %w", err)
	}
	return string(bytes.TrimSpace(fbytes)), nil
}

// loadPrivateKey reads and parses the private key from the given file.
func loadPrivateKey(file string) (*rsa.PrivateKey, error) {
	// Load the private key from the file
	keyBytes, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("could not read private key file: %w", err)
	}
	// Parse the private key
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse private key: %w", err)
	}
	return privateKey, nil
}
