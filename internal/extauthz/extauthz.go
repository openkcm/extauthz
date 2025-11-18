package extauthz

import (
	"context"
	"errors"

	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/openkcm/session-manager/pkg/session"
	"github.com/samber/oops"

	"github.com/openkcm/extauthz/internal/clientdata"
	"github.com/openkcm/extauthz/internal/oidc"
	"github.com/openkcm/extauthz/internal/policies"
	"github.com/openkcm/extauthz/internal/policies/cedarpolicy"
)

const (
	DefaultCMKPathPrefix = "/cmk/v1/"
)

// sessionLoaderInterface defines the interface for loading sessions.
// We don't use session.Repository directly to avoid depending on
// unnecessary methods and to make testing easier.
type sessionLoaderInterface interface {
	LoadSession(ctx context.Context, sessionID string) (session.Session, error)
}

// oidcHandlerInterface defines the interface for OIDC handling.
// We don't use oidc.Handler directly to make testing easier.
type oidcHandlerInterface interface {
	ParseAndValidate(ctx context.Context, rawToken string, userclaims any, useCache bool) error
	Introspect(ctx context.Context, issuer, introspectToken string, useCache bool) (oidc.Introspection, error)
}

type Server struct {
	policyEngine           policies.Engine
	oidcHandler            oidcHandlerInterface
	clientDataSigner       *clientdata.Signer
	trustedSubjectToRegion map[string]string
	featureGates           *commoncfg.FeatureGates
	sessionCache           sessionLoaderInterface
	cmkPathPrefix          string
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

func WithSessionCache(sessionCache sessionLoaderInterface) ServerOption {
	return func(server *Server) error {
		server.sessionCache = sessionCache
		return nil
	}
}

func WithCMKPathPrefix(cmkPathPrefix string) ServerOption {
	return func(server *Server) error {
		server.cmkPathPrefix = cmkPathPrefix
		return nil
	}
}

// NewServer creates a new server and applies the given options.
func NewServer(opts ...ServerOption) (*Server, error) {
	policyEngine, err := cedarpolicy.NewEngine(cedarpolicy.WithBytes("empty", []byte("")))
	if err != nil {
		return nil, oops.Hint("failed to create policy engine").Wrap(err)
	}

	hdl, err := oidc.NewHandler()
	if err != nil {
		return nil, oops.Hint("failed to create OIDC handler").Wrap(err)
	}

	server := &Server{
		policyEngine:  policyEngine,
		oidcHandler:   hdl,
		cmkPathPrefix: DefaultCMKPathPrefix,
		featureGates:  &commoncfg.FeatureGates{},
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
	if s.clientDataSigner != nil {
		err := s.clientDataSigner.Close()
		if err != nil {
			return oops.Hint("failed to stop the signing key loader").Wrap(err)
		}
	}

	return nil
}
