package clientdata

import (
	"errors"
	"fmt"

	"github.com/openkcm/common-sdk/pkg/auth"
	"github.com/openkcm/common-sdk/pkg/commoncfg"

	"github.com/openkcm/extauthz/internal/clientdata/signing"
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
	EnrichHeaderWithClientType   = "enrich-header-with-client-type"
	DisableClientDataComputation = "disable-client-data-computation"
)

var (
	ErrComputationNotEnabled = errors.New("computation of client data not enabled")
)

type Factory struct {
	enabled      bool
	featureGates *commoncfg.FeatureGates
	signingKey   *signing.Key
}

func NewFactory(featureGates *commoncfg.FeatureGates, cfg *config.ClientData) (*Factory, error) {
	cdcDisabled := featureGates.IsFeatureEnabled(DisableClientDataComputation)
	if cdcDisabled {
		return &Factory{}, nil
	}

	// Load the private key for signing the client data
	signingKey, err := signing.FromFile(cfg.SigningKeyIDFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load signing key: %w", err)
	}

	return NewFactoryWithSigningKey(featureGates, signingKey), nil
}

func NewFactoryWithSigningKey(featureGates *commoncfg.FeatureGates, signingKey *signing.Key) *Factory {
	cdcDisabled := featureGates.IsFeatureEnabled(DisableClientDataComputation)
	if cdcDisabled {
		return &Factory{}
	}

	return &Factory{
		enabled:      true,
		signingKey:   signingKey,
		featureGates: featureGates,
	}
}

func (c *Factory) SigningKeyID() string {
	if c.IsDisabled() {
		return ""
	}

	return c.signingKey.ID
}

func (c *Factory) Enabled() bool {
	return c.enabled
}

func (c *Factory) IsDisabled() bool {
	return !c.enabled
}

func (c *Factory) Create(opts ...Option) (*auth.ClientData, error) {
	if c.IsDisabled() {
		return nil, ErrComputationNotEnabled
	}

	builder := &clientDataBuilder{
		ClientData: auth.ClientData{
			SignatureAlgorithm: auth.SignatureAlgorithmRS256,
			KeyID:              c.SigningKeyID(),
		},
		factory: c,
	}

	for _, opt := range opts {
		err := opt(builder)
		if err != nil {
			return nil, err
		}
	}

	return &builder.ClientData, nil
}

func (c *Factory) CreateAndEncode(opts ...Option) (string, string, error) {
	cd, err := c.Create(opts...)
	if err != nil {
		return "", "", err
	}

	return cd.Encode(c.signingKey.Private)
}
