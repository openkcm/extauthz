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

	// Valkey cache to collect request rate metrics.
	Valkey Valkey `yaml:"valkey"`
}

type Valkey struct {
	Address   commoncfg.SourceRef `yaml:"address" json:"address"`
	User      commoncfg.SourceRef `yaml:"user"`
	Password  commoncfg.SourceRef `yaml:"password"`
	Prefix    string              `yaml:"prefix"`
	SecretRef commoncfg.SecretRef `yaml:"secretRef"`

	// RateDetection configures the cross-pod detection of unauthenticated
	// request bursts. When disabled the whole feature is a no-op and Valkey is
	// never contacted.
	RateDetection RateDetection `yaml:"rateDetection"`
}

// RateDetection configures threshold-over-window detection of unauthenticated
// request bursts. Crossing Threshold within Window emits a single audit event
// across the fleet, suppressed for Cooldown.
type RateDetection struct {
	// Enabled turns the unauthenticated-burst detection on. When false the
	// Valkey rate store is not created and no burst events are emitted.
	Enabled bool `yaml:"enabled"`

	// Threshold is the number of unauthenticated requests for the same identity
	// within Window that triggers a single audit event.
	Threshold int64 `yaml:"threshold" default:"50"`

	// Window is the tumbling window over which requests are counted.
	Window time.Duration `yaml:"window" default:"1m"`

	// Cooldown is how long a fired event suppresses further events for the same
	// identity and window. Defaults to Window when unset. It should be >= Window,
	// otherwise the suppression latch expires before the window rolls over and a
	// single burst can emit multiple events.
	Cooldown time.Duration `yaml:"cooldown"`

	// CountUnknown includes UNKNOWN results (no credentials presented at all) in
	// the burst count. Off by default so health probes and anonymous public
	// traffic are not counted as auth failures.
	CountUnknown bool `yaml:"countUnknown"`

	// QueueSize bounds the async audit dispatch queue. When full, events are
	// dropped and counted rather than blocking the Check() hot path.
	QueueSize int `yaml:"queueSize" default:"1024"`

	// Workers is the number of goroutines draining the audit dispatch queue.
	Workers int `yaml:"workers" default:"4"`

	// DispatchTimeout bounds how long a single queued audit job (Valkey observe
	// + audit send) may run before its context is cancelled, so a hung backend
	// cannot permanently occupy a worker.
	DispatchTimeout time.Duration `yaml:"dispatchTimeout" default:"10s"`
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
	IssuerClaimKeys []string `yaml:"issuerClaimKeys" default:"[\"iss\"]"`

	// A list of static JWT providers
	Providers []Provider `yaml:"providers"`

	// OAuth2 template configuration - the OAuth2 client builder will dynamically
	// create http clients from this based on the client ID of tenant trusts.
	OAuth2 commoncfg.OAuth2 `yaml:"oauth2"`

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
