package config

import (
	"github.com/openkcm/common-sdk/pkg/commoncfg"
)

type Config struct {
	commoncfg.BaseConfig `mapstructure:",squash"`

	// gRPC server configuration
	GRPCServer GRPCServer `yaml:"grpcServer"`

	// Cedar configuration
	Cedar Cedar `yaml:"cedar"`

	// Client Certificate handling
	MTLS MTLS `yaml:"mtls"`

	// JWT Token handling
	JWT JWT `yaml:"jwt"`

	// ClientData configuration
	ClientData ClientData `yaml:"clientData"`

	// Session cache configuration (optional)
	SessionCache SessionCache `yaml:"sessionCache"`
}

type SessionCache struct {
	Valkey *Valkey `yaml:"valkey"`
}

type Valkey struct {
	Host     commoncfg.SourceRef `yaml:"host"`
	User     commoncfg.SourceRef `yaml:"user"`
	Password commoncfg.SourceRef `yaml:"password"`
	Prefix   string              `yaml:"prefix"`
}

// ClientData configuration
type ClientData struct {
	// SigningKeyIDFilePath is the file containing the key ID for the signing key.
	// The key itself is expected in the same directory as <keyID>.pem.
	// The loading is based on the internal/signing package.
	// The signing itself is based on github.com/openkcm/common-sdk/pkg/auth.
	SigningKeyIDFilePath string `yaml:"signingKeyIDFilePath"`
}

// Cedar configuration
type Cedar struct {
	// PolicyPath is the path to Cedar policy files
	PolicyPath string
}

// GRPCServer server configuration
type GRPCServer struct {
	commoncfg.GRPCServer `mapstructure:",squash"`

	// also embed client attributes for the gRPC health check client
	Client commoncfg.GRPCClient
}

type MTLS struct {
	// TrustedSubjectsYaml is a path to a YAML file holding a list of
	// trusted client certificate subjects and their respective regions.
	TrustedSubjectsYaml string
}

type JWT struct {
	// IssuerClaimKeys configures the JWT issuer keys
	IssuerClaimKeys []string `yaml:"issuerClaimKeys" default:"['iss']"`

	// A list of static JWT providers
	Providers []Provider `yaml:"providers"`

	// An optional gRPC source to dynamically lookup JWT providers
	ProviderSource *ProviderSource `yaml:"providerSource"`
}

type ProviderSource struct {
	commoncfg.GRPCClient `mapstructure:",squash"`

	// Only MTLS and Insecure are supported
	SecretRef commoncfg.SecretRef `yaml:"secretRef"`
}

type Provider struct {
	Issuer    string   `yaml:"issuer"`
	Audiences []string `yaml:"audiences"`
	JwksURIs  []string `yaml:"jwksURIs"`
}
