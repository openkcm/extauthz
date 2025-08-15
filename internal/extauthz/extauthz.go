package extauthz

import (
	"errors"
	"fmt"

	"github.com/openkcm/common-sdk/pkg/commoncfg"

	"github.com/openkcm/extauthz/internal/jwthandler"
	"github.com/openkcm/extauthz/internal/policy"
	"github.com/openkcm/extauthz/internal/signing"
)

type policyEngine interface {
	Check(subject, action, resource string, cntxt map[string]string) (bool, string, error)
}

type Server struct {
	policyEngine           policyEngine
	jwtHandler             *jwthandler.Handler
	trustedSubjectToRegion map[string]string
	signingKey             *signing.Key
	featureGates           *commoncfg.FeatureGates
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

func WithJWTHandler(hdl *jwthandler.Handler) ServerOption {
	return func(server *Server) error {
		if hdl == nil {
			return errors.New("jwt handler must not be nil")
		}

		server.jwtHandler = hdl

		return nil
	}
}

func WithPolicyEngine(pe policyEngine) ServerOption {
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

// NewServer creates a new server and applies the given options.
func NewServer(signingKey *signing.Key, opts ...ServerOption) (*Server, error) {
	policyEngine, err := policy.NewEngine(policy.WithBytes("empty", []byte("")))
	if err != nil {
		return nil, fmt.Errorf("failed to create policy engine: %w", err)
	}

	hdl, err := jwthandler.NewHandler()
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT handler: %w", err)
	}

	server := &Server{
		policyEngine: policyEngine,
		jwtHandler:   hdl,
		signingKey:   signingKey,
	}
	for _, opt := range opts {
		err := opt(server)
		if err != nil {
			return nil, err
		}
	}

	return server, nil
}
