package config

import (
	"time"

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

	// Client data key set server
	CDKSServer ClientDataKeySetServer `yaml:"cdksServer"`
}

// Cedar configuration
type Cedar struct {
	// PolicyPath is the path to Cedar policy files
	PolicyPath string
}

// gRPC server configuration
type GRPCServer struct {
	commoncfg.GRPCServer `mapstructure:",squash"`

	// also embed client attributes for the gRPC health check client
	ClientAttributes commoncfg.GRPCClientAttributes
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
	K8sProviders K8sProviders `yaml:"k8sProviders"`
}

type K8sProviders struct {
	Enabled    bool   `yaml:"enabled" default:"true"`
	APIGroup   string `yaml:"apiGroup" default:"gateway.extensions.envoyproxy.io"`
	APIVersion string `yaml:"apoVersion" default:"v1alpha1"`
	Name       string `yaml:"name" default:"jwtproviders"`
	Namespace  string `yaml:"namespace" default:"default"`
}

// ClientDataKeySetServer defines the information passed as header to consuming backend services.
// It is based on github.com/openkcm/common-sdk/pkg/auth.
// The Client Data Key Set (CDKSServer) is a set of keys containing the public keys used to verify any Client data Token (CDT)
// issued by the ExtAuthZ
type ClientDataKeySetServer struct {
	// Address is the address, which provides the public key used to
	// validate the client data signature.
	Address string `json:"address" default:":5555"`
	// SigningKeyRefreshInterval is the interval in seconds to refresh the signing key.
	SigningKeyRefreshInterval time.Duration `yaml:"signingKeyRefreshInterval" default:"6h"`
}
