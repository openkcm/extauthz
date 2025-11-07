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
	Enabled       bool   `yaml:"enabled"`
	Valkey        Valkey `yaml:"valkey"`
	CMKPathPrefix string `yaml:"cmkPathPrefix"`
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

	// Define providers as k8s custom resources
	// Deprecated: use Providers and ProviderSource instead
	K8sProviders K8sProviders `yaml:"k8sProviders"`

	// A list of static JWT providers
	Providers []Provider `yaml:"providers"`

	// An optional gRPC source to dynamically lookup JWT providers
	ProviderSource commoncfg.GRPCClient `yaml:"providerSource"`
}

// Deprecated: use Providers and ProviderSource instead
type K8sProviders struct {
	Enabled    bool   `yaml:"enabled" default:"true"`
	APIGroup   string `yaml:"apiGroup" default:"gateway.extensions.envoyproxy.io"`
	APIVersion string `yaml:"apoVersion" default:"v1alpha1"`
	Name       string `yaml:"name" default:"jwtproviders"`
	Namespace  string `yaml:"namespace" default:"default"`
}

type Provider struct {
	Issuer                string   `yaml:"issuer"`
	Audiences             []string `yaml:"audiences"`
	JwksURI               string   `yaml:"jwksURI"`
	IntrospectionEndpoint string   `yaml:"introspectionEndpoint"`
}
