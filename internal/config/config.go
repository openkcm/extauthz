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
}

type Provider struct {
	// Usually a URL identifying the OIDC provider, but can technically be any string.
	Issuer string `yaml:"issuer"`

	// Set IssuerURI if issuer is not a valid URI.
	IssuerURI string `yaml:"issuerURI"`

	// Set JwksURI if you want to avoid OIDC discovery.
	JwksURI string `yaml:"jwksURI"`

	// List of audiences to validate in the token.
	// Optional, if not set, no audience validation will be performed.
	Audiences []string `yaml:"audiences"`

	// DisableTokenIntrospection: if set to true, will disable token introspection.
	DisableTokenIntrospection bool `yaml:"disableTokenIntrospection"`
}
