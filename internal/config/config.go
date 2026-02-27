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

	// SessionPathPrefixes configures http path prefixes for which we expect
	// sessions and which have the tenant ID as next path segment e.g.
	// - /lvl1       will match paths like /lvl1/{tenantID}/...
	// - /lvl1/lvl2  will match paths like /lvl1/lvl2{tenantID}/...
	SessionPathPrefixes []string `yaml:"sessionPathPrefixes"`

	// Session Manager configuration (optional)
	SessionManager commoncfg.GRPCClient `yaml:"sessionManager"`

	// CSRFSecret is a key using to generate the CSRF token.
	CSRFSecret commoncfg.SourceRef `yaml:"csrfSecret"`
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

	// HTTP client configuration for interacting with OIDC providers
	HTTPClient commoncfg.HTTPClient `yaml:"httpClient"`

	// Define providers as k8s custom resources
	// Deprecated: use Providers and ProviderSource instead
	K8sProviders K8sProviders `yaml:"k8sProviders"`
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
	Issuer    string   `yaml:"issuer"`
	IssuerURI string   `yaml:"issuerURI"` // Optional: set if issuer is not a valid URI
	JwksURI   string   `yaml:"jwksURI"`   // Optional: set if you want to avoid OIDC discovery
	Audiences []string `yaml:"audiences"`
}
