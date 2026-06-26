package extauthz

import (
	"context"
	"errors"
	"strings"

	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/samber/oops"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"

	"github.com/openkcm/extauthz/internal/clientdata"
	"github.com/openkcm/extauthz/internal/handler"
	"github.com/openkcm/extauthz/internal/policies"
	"github.com/openkcm/extauthz/internal/policies/cedarpolicy"
	"github.com/openkcm/extauthz/internal/session"
)

// tracerName is the OTel instrumentation library name used for the
// application span emitted by Check(). Using the module path follows the
// OTel Go convention.
const tracerName = "github.com/openkcm/extauthz"

const (
	DefaultCMKPathPrefix = "/cmk/v1/"

	// Context data keys for policy engine
	contextKeyHost   = "host"
	contextKeyPath   = "path"
	contextKeyType   = "type"
	contextKeyIssuer = "issuer"

	// Auth type values
	authTypeX509 = "x509"
	authTypeJWT  = "jwt"
)

// sessionManagerInterface defines the interface for the session manager.
// We don't use session.Manager directly to make testing easier.
type sessionManagerInterface interface {
	GetSession(ctx context.Context, sessionID, tenantID string) (*session.Session, error)
}

// oidcHandlerInterface defines the interface for OIDC handling.
// We don't use handler.OIDC directly to make testing easier.
type oidcHandlerInterface interface {
	ParseAndValidate(ctx context.Context, rawToken, tenantID string, userclaims any, useCache bool) error
}

type Server struct {
	policyEngine           policies.Engine
	oidcHandler            oidcHandlerInterface
	clientDataSigner       *clientdata.Signer
	trustedSubjectToRegion map[string]string
	featureGates           *commoncfg.FeatureGates
	sessionManager         sessionManagerInterface
	sessionPathPrefixes    []string
	csrfSecret             []byte
	tracer                 trace.Tracer
	cancel                 context.CancelFunc
}

// ServerOption is used to configure a server.
type ServerOption func(*Server) error

func WithTrustedSubjects(m map[string]string) ServerOption {
	return func(server *Server) error {
		if m == nil {
			return errors.New("trusted subjects map must not be nil")
		}

		server.trustedSubjectToRegion = m

		return nil
	}
}

func WithOIDCHandler(hdl oidcHandlerInterface) ServerOption {
	return func(server *Server) error {
		if hdl == nil {
			return errors.New("OIDC handler must not be nil")
		}

		server.oidcHandler = hdl

		return nil
	}
}

func WithClientDataSigner(cdp *clientdata.Signer) ServerOption {
	return func(server *Server) error {
		if cdp == nil {
			return errors.New("client data factory must not be nil")
		}

		server.clientDataSigner = cdp

		return nil
	}
}

func WithPolicyEngine(pe policies.Engine) ServerOption {
	return func(server *Server) error {
		if pe == nil {
			return errors.New("policy engine must not be nil")
		}

		server.policyEngine = pe

		return nil
	}
}

func WithFeatureGates(fg *commoncfg.FeatureGates) ServerOption {
	return func(server *Server) error {
		server.featureGates = fg
		return nil
	}
}

func WithSessionManager(sessionManager sessionManagerInterface) ServerOption {
	return func(server *Server) error {
		server.sessionManager = sessionManager
		return nil
	}
}

func WithSessionPathPrefixes(sessionPathPrefixes []string) ServerOption {
	return func(server *Server) error {
		// make sure they have a trailing /
		sessionPathPrefixesCopy := make([]string, len(sessionPathPrefixes))
		for i, p := range sessionPathPrefixes {
			if !strings.HasSuffix(p, "/") {
				p += "/"
			}
			sessionPathPrefixesCopy[i] = p
		}
		server.sessionPathPrefixes = sessionPathPrefixesCopy
		return nil
	}
}

func WithCSRFSecret(secret []byte) ServerOption {
	return func(server *Server) error {
		server.csrfSecret = secret
		return nil
	}
}

// WithTracer overrides the default OpenTelemetry tracer used to emit the
// per-Check application span. The default tracer is obtained from the
// global TracerProvider at NewServer time (see NewServer). Tests use this
// option to inject an SDK tracer backed by an in-memory exporter.
func WithTracer(t trace.Tracer) ServerOption {
	return func(server *Server) error {
		if t == nil {
			return errors.New("tracer must not be nil")
		}

		server.tracer = t

		return nil
	}
}

// NewServer creates a new server and applies the given options.
func NewServer(opts ...ServerOption) (*Server, error) {
	policyEngine, err := cedarpolicy.NewEngine(cedarpolicy.WithBytes("empty", []byte("")))
	if err != nil {
		return nil, oops.Hint("failed to create policy engine").Wrap(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	hdl, err := handler.NewOIDC(ctx)
	if err != nil {
		cancel()
		return nil, oops.Hint("failed to create OIDC handler").Wrap(err)
	}

	server := &Server{
		policyEngine:        policyEngine,
		oidcHandler:         hdl,
		sessionPathPrefixes: []string{},
		featureGates:        &commoncfg.FeatureGates{},
		cancel:              cancel,
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		err := opt(server)
		if err != nil {
			return nil, err
		}
	}

	// Default tracer is acquired from the global TracerProvider after options
	// have been applied so WithTracer can override it. Acquiring it at
	// construction time (rather than at import time) ensures we observe the
	// real TracerProvider installed by otlp.Init during process startup.
	if server.tracer == nil {
		server.tracer = otel.Tracer(tracerName)
	}

	return server, nil
}

// Start starts any internal processes required by the server.
func (s *Server) Start() error {
	if s.clientDataSigner != nil {
		err := s.clientDataSigner.Start()
		if err != nil {
			return oops.Hint("failed to start the signing key loader").Wrap(err)
		}
	}
	return nil
}

// Close starts any internal processes required by the server.
func (s *Server) Close() error {
	s.cancel()
	if s.clientDataSigner != nil {
		err := s.clientDataSigner.Close()
		if err != nil {
			return oops.Hint("failed to stop the signing key loader").Wrap(err)
		}
	}

	return nil
}
