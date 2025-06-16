package signing

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

type signingKey struct {
	keyID  string
	priv   *rsa.PrivateKey
	pub    *rsa.PublicKey
	m      *sync.Mutex
	ticker *time.Ticker
}

// Option is used to configure a singing key.
type Option func(*signingKey) error

// WithRefreshInterval specifies the interval to refresh the key pair.
func WithRefreshInterval(interval time.Duration) Option {
	return func(sk *signingKey) error {
		if interval <= 0 {
			return fmt.Errorf("refresh interval must be greater than zero, got %v", interval)
		}
		sk.ticker = time.NewTicker(interval)
		return nil
	}
}

// NewKey creates a new signing key with the specified options.
func NewKey(ctx context.Context, opts ...Option) (*signingKey, error) {
	sk := &signingKey{
		m: &sync.Mutex{},
	}
	for _, opt := range opts {
		if err := opt(sk); err != nil {
			return nil, fmt.Errorf("could not apply option: %w", err)
		}
	}
	if err := sk.genKeyPair(); err != nil {
		return nil, fmt.Errorf("could not generate key pair: %w", err)
	}
	if sk.ticker != nil {
		go func() {
			for {
				select {
				case <-ctx.Done():
					slog.Info("Stopping signing key refresh")
					sk.ticker.Stop()
					return
				case <-sk.ticker.C:
					slog.Info("Refreshing signing key")
					if err := sk.genKeyPair(); err != nil {
						slog.Error("could not refresh signing key", "error", err)
					}
				}
			}
		}()
	}
	return sk, nil
}

func (sk *signingKey) genKeyPair() error {
	// Generate a new RSA key pair and key ID
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("could not generate RSA key pair: %w", err)
	}
	publicKey := &privateKey.PublicKey
	keyID := uuid.New().String()
	slog.Info("Generated new signing key", "keyID", keyID)

	// Set them
	sk.m.Lock()
	defer sk.m.Unlock()
	sk.keyID = keyID
	sk.priv = privateKey
	sk.pub = publicKey
	return nil
}

// Private returns the ID and private key of the signing key.
func (sk *signingKey) Private() (string, *rsa.PrivateKey, error) {
	sk.m.Lock()
	defer sk.m.Unlock()
	if sk.priv == nil {
		return "", nil, fmt.Errorf("private key not generated")
	}
	return sk.keyID, sk.priv, nil
}

// PublicPEM returns the ID and PEM-encoded public key of the signing key.
func (sk *signingKey) PublicPEM() (string, string, error) {
	sk.m.Lock()
	defer sk.m.Unlock()
	if sk.pub == nil {
		return "", "", fmt.Errorf("public key not generated")
	}
	pubKeyDER, err := x509.MarshalPKIXPublicKey(sk.pub)
	if err != nil {
		return "", "", fmt.Errorf("could not marshal RSA public key: %w", err)
	}
	pubKeyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyDER,
	}))
	return sk.keyID, pubKeyPEM, nil
}

type responsePublicKey struct {
	KeyID  string `json:"id"`
	KeyPEM string `json:"pem"`
}

type responsePublicKeys struct {
	Keys []responsePublicKey `json:"keys"`
}

// ServePublicKey starts an HTTP server that serves the public key of the signing key.
func (sk *signingKey) ServePublicKey(ctx context.Context, address string) error {
	if address == "" {
		return fmt.Errorf("address cannot be empty")
	}
	srv := &http.Server{
		Addr: address,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// get the key ID and public key
			keyID, pubKeyPEM, err := sk.PublicPEM()
			if err != nil {
				http.Error(w, "could not get public key", http.StatusInternalServerError)
				return
			}

			// create the response
			response := responsePublicKeys{
				Keys: []responsePublicKey{
					{
						KeyID:  keyID,
						KeyPEM: pubKeyPEM,
					},
				},
			}

			// encode and return the response as JSON
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			//nolint:errcheck
			json.NewEncoder(w).Encode(response)
		}),
	}

	// start the server in a goroutine
	go func() {
		slog.Info("Starting HTTP server for serving the public key", "address", address)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Error serving HTTP endpoint", "error", err)
		}
		slog.Info("Stopped HTTP server for serving the public key")
	}()

	// wait for the context to be done
	<-ctx.Done()
	shutdownCtx, shutdownRelease := context.WithTimeout(ctx, 5*time.Second)
	defer shutdownRelease()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("failed to gracefully shutdown HTTP server for serving the public key: %w", err)
	}
	slog.Info("Completed graceful shutdown of HTTP server for serving the public key")
	return nil
}
