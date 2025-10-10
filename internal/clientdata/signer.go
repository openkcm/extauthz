package clientdata

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openkcm/common-sdk/pkg/auth"
	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/openkcm/common-sdk/pkg/commonfs/loader"
	"github.com/openkcm/common-sdk/pkg/storage/keyvalue"

	"github.com/openkcm/extauthz/internal/config"
)

type ClientType string

const (
	User          ClientType = "user"
	TechnicalUser ClientType = "technical-user"
	System        ClientType = "system"

	// EnrichHeaderWithClientRegion if set on true is including the client region. information in the headers
	EnrichHeaderWithClientRegion = "enrich-header-with-client-region"
	// EnrichHeaderWithClientType if set on true is including the client type. information in the headers
	EnrichHeaderWithClientType = "enrich-header-with-client-type"
	// DisableClientDataComputation if set on true the client data is not generated on the headers
	DisableClientDataComputation = "disable-client-data-computation"
)

var (
	ErrComputationNotEnabled = errors.New("computation of client data not enabled")
)

type Signer struct {
	enabled      bool
	featureGates *commoncfg.FeatureGates

	keyIdFileName    string
	signingKeyLoader *loader.Loader
}

func NewSigner(featureGates *commoncfg.FeatureGates, cfg *config.ClientData) (*Signer, error) {
	cdcDisabled := featureGates.IsFeatureEnabled(DisableClientDataComputation)
	if cdcDisabled {
		return &Signer{}, nil
	}

	path, keyIDFileName := filepath.Split(cfg.SigningKeyIDFilePath)

	signingKeyLoader, err := loader.Create(
		loader.OnPath(path),
		loader.WithKeyIDType(loader.FileNameWithExtension),
		loader.WithStorage(keyvalue.NewMemoryStorage[string, []byte]()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load signing key: %w", err)
	}

	return &Signer{
		enabled:          true,
		keyIdFileName:    keyIDFileName,
		signingKeyLoader: signingKeyLoader,
		featureGates:     featureGates,
	}, nil
}

func (c *Signer) SigningKeyID() string {
	if c.IsDisabled() {
		return ""
	}

	return c.keyIdFileName
}

func (c *Signer) Enabled() bool {
	return c.enabled
}

func (c *Signer) IsDisabled() bool {
	return !c.enabled
}

func (c *Signer) Sign(opts ...Option) (string, string, error) {
	fbytes, exist := c.signingKeyLoader.Storage().Get(c.keyIdFileName)
	if !exist {
		return "", "", fmt.Errorf("signing key with ID %q not found in storage", c.keyIdFileName)
	}

	keyIDName := string(bytes.TrimSpace(fbytes))

	keyBytes, exist := c.lookupByKeys(keyIDName, keyIDName+".pem")
	if !exist {
		return "", "", fmt.Errorf("signing key with ID %q not found in storage", keyIDName)
	}

	// Parse the private key
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse private key: %w", err)
	}

	cd, err := c.create(opts...)
	if err != nil {
		return "", "", err
	}

	return cd.Encode(privateKey)
}

func (c *Signer) Start() error {
	if c.IsDisabled() {
		return nil
	}

	return c.signingKeyLoader.Start()
}

func (c *Signer) Close() error {
	if c.IsDisabled() {
		return nil
	}

	return c.signingKeyLoader.Close()
}

func (c *Signer) lookupByKeys(keys ...string) ([]byte, bool) {
	for _, key := range keys {
		keyBytes, exist := c.signingKeyLoader.Storage().Get(key)
		if exist {
			return keyBytes, true
		}
	}

	return nil, false
}

func (c *Signer) create(opts ...Option) (*auth.ClientData, error) {
	if c.IsDisabled() {
		return nil, ErrComputationNotEnabled
	}

	builder := &clientDataBuilder{
		ClientData: auth.ClientData{
			SignatureAlgorithm: auth.SignatureAlgorithmRS256,
			KeyID:              c.SigningKeyID(),
		},
		signer: c,
	}

	for _, opt := range opts {
		err := opt(builder)
		if err != nil {
			return nil, err
		}
	}

	return &builder.ClientData, nil
}
