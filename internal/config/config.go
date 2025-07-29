package config

import (
	"github.com/openkcm/common-sdk/pkg/commoncfg"
)

type Config struct {
	commoncfg.BaseConfig `mapstructure:",squash"`

	// gRPC server configuration
	GRPCServer GRPCServer

	// Cedar configuration
	Cedar Cedar

	// Client Certificate handling
	MTLS MTLS

	// JWT Token handling
	JWT JWT

	// Client data handling
	ClientData ClientData
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
	IssuerClaimKeys []string `yaml:"issuerClaimKeys"`

	// Define providers as k8s custom resources
	K8sProviders K8sProviders `yaml:"k8sProviders"`
}

type K8sProviders struct {
	APIGroup   string // e.g. "gateway.extensions.envoyproxy.io"
	APIVersion string // e.g. "v1alpha1"
	Name       string // e.g. "jwtproviders"
	Namespace  string // e.g. "default"
}

// ClientData defines the information passed as header to consuming backend services.
// It is based on github.com/openkcm/common-sdk/pkg/auth.
type ClientData struct {
	// PublicKeyAddress is the address, which provides the public key used to
	// validate the client data signature.
	PublicKeyAddress string
	// SigningKeyRefreshIntervalS is the interval in seconds to refresh the signing key.
	SigningKeyRefreshIntervalS int64
	// WithRegion will include the client certificate region
	WithRegion bool
	// WithType will include the type of user
	WithType bool
}
