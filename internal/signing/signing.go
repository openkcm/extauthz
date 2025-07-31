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
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	slogctx "github.com/veqryn/slog-context"
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
		err := opt(sk)
		if err != nil {
			return nil, fmt.Errorf("could not apply option: %w", err)
		}
	}

	err := sk.genKeyPair()
	if err != nil {
		return nil, fmt.Errorf("could not generate key pair: %w", err)
	}

	slogctx.Info(ctx, "Generated new signing key", "keyID", sk.keyID)

	if sk.ticker != nil {
		go func() {
			for {
				select {
				case <-ctx.Done():
					slogctx.Info(ctx, "Stopping signing key refresh")
					sk.ticker.Stop()

					return
				case <-sk.ticker.C:
					slogctx.Info(ctx, "Refreshing signing key")

					err := sk.genKeyPair()
					if err != nil {
						slogctx.Error(ctx, "could not refresh signing key", "error", err)
					}
				}
			}
		}()
	}

	return sk, nil
}

// Private returns the ID and private key of the signing key.
func (sk *signingKey) Private() (string, *rsa.PrivateKey, error) {
	sk.m.Lock()
	defer sk.m.Unlock()

	if sk.priv == nil {
		return "", nil, errors.New("private key not generated")
	}

	return sk.keyID, sk.priv, nil
}

// PublicPEM returns the ID and PEM-encoded public key of the signing key.
func (sk *signingKey) PublicPEM() (string, string, error) {
	sk.m.Lock()
	defer sk.m.Unlock()

	if sk.pub == nil {
		return "", "", errors.New("public key not generated")
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
		return errors.New("address cannot be empty")
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

			err = json.NewEncoder(w).Encode(response)
			if err != nil {
				http.Error(w, "could not encode response", http.StatusInternalServerError)
				return
			}
		}),
	}

	// start the server in a goroutine
	go func() {
		slogctx.Info(ctx, "Starting HTTP server for serving the public key", "address", address)

		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slogctx.Error(ctx, "Error serving HTTP endpoint", "error", err)
		}

		slogctx.Info(ctx, "Stopped HTTP server for serving the public key")
	}()

	// wait for the context to be done
	<-ctx.Done()

	shutdownCtx, shutdownRelease := context.WithTimeout(ctx, 5*time.Second)
	defer shutdownRelease()

	err := srv.Shutdown(shutdownCtx)
	if err != nil {
		return fmt.Errorf("failed to gracefully shutdown HTTP server for serving the public key: %w", err)
	}

	slogctx.Info(ctx, "Completed graceful shutdown of HTTP server for serving the public key")

	return nil
}

func (sk *signingKey) genKeyPair() error {
	// Generate a new RSA key pair and key ID
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("could not generate RSA key pair: %w", err)
	}

	publicKey := &privateKey.PublicKey
	keyID := uuid.New().String()

	// Set them
	sk.m.Lock()
	defer sk.m.Unlock()

	sk.keyID = keyID
	sk.priv = privateKey
	sk.pub = publicKey

	return nil
}
