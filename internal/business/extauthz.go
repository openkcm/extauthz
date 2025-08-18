package business

import (
	"context"
	"fmt"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/extauthz/internal/clientdata"
	"github.com/openkcm/extauthz/internal/config"
	"github.com/openkcm/extauthz/internal/extauthz"
	"github.com/openkcm/extauthz/internal/jwthandler"
	"github.com/openkcm/extauthz/internal/policies/cedarpolicy"
)

func createExtAuthZServer(ctx context.Context, cfg *config.Config) (*extauthz.Server, error) {
	// Load the private key for signing the client data
	clientDataFactory, err := clientdata.NewFactory(&cfg.FeatureGates, &cfg.ClientData)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientdata: %w", err)
	}

	if clientDataFactory.Enabled() {
		slogctx.Info(ctx, "Using client data with signing key", "id", clientDataFactory.SigningKeyID())
	} else {
		slogctx.Info(ctx, "Using client data has been disabled")
	}

	// Load all Cedar policy files from the policy path
	slogctx.Info(ctx, "Handling cedar policies", "cedar", cfg.Cedar)

	pe, err := cedarpolicy.NewEngine(cedarpolicy.WithPath(cfg.Cedar.PolicyPath))
	if err != nil {
		return nil, fmt.Errorf("failed to create the policy engine: %w", err)
	}
	// Load the trusted subjects
	subjects, err := loadTrustedSubjects(cfg.MTLS.TrustedSubjectsYaml)
	if err != nil {
		return nil, fmt.Errorf("failed to load trusted subjects: %w", err)
	}

	if len(cfg.JWT.IssuerClaimKeys) == 0 {
		slogctx.Warn(ctx, "JWT configuration doesn't have the issuer claims keys; Use the default values: [iss].")

		cfg.JWT.IssuerClaimKeys = jwthandler.DefaultIssuerClaims
	}

	// Create the JWT handler
	slogctx.Debug(ctx, "Using k8s JWT providers", "k8s", cfg.JWT.K8sProviders)

	hdl, err := jwthandler.NewHandler(
		jwthandler.WithIssuerClaimKeys(cfg.JWT.IssuerClaimKeys...),
		jwthandler.WithK8sJWTProviders(
			cfg.JWT.K8sProviders.Enabled,
			cfg.JWT.K8sProviders.APIGroup,
			cfg.JWT.K8sProviders.APIVersion,
			cfg.JWT.K8sProviders.Name,
			cfg.JWT.K8sProviders.Namespace,
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create the JWT handler: %w", err)
	}

	// Create the ExtAuthZ server
	srv, err := extauthz.NewServer(
		extauthz.WithPolicyEngine(pe),
		extauthz.WithJWTHandler(hdl),
		extauthz.WithClientDataFactory(clientDataFactory),
		extauthz.WithTrustedSubjects(subjects),
		extauthz.WithFeatureGates(&cfg.FeatureGates),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create the ExtAuthZ server: %w", err)
	}

	return srv, nil
}
