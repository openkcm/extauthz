package config

import (
	"github.com/openkcm/common-sdk/pkg/commoncfg"
)

type Config struct {
	commoncfg.BaseConfig `mapstructure:",squash"`

	// gRPC server configuration
	GRPCServer GRPCServer

	// PolicyPath is the path to Cedar policy files
	PolicyPath string

	// Client Certificate handling
	MTLS MTLS

	// JWT Token handling
	JWT JWT

	// Client data handling
	ClientData ClientData
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

type JWTOperationMode string

const (
	JWTOperationModeDefault JWTOperationMode = "default"
	JWTOperationModeSapias  JWTOperationMode = "sapias"
)

type JWT struct {
	// OperationMode configures the JWT validation according to the
	// JWT provider. One of default, sapias
	OperationMode JWTOperationMode

	// Define providers as k8s custom resources
	K8sProviders K8sProviders
}

type K8sProviders struct {
	APIGroup  string
	Name      string
	Namespace string
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
