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
	// prepare the options for the server
	ops := []extauthz.ServerOption{
		extauthz.WithFeatureGates(&cfg.FeatureGates),
	}

	// Load the private key for signing the client data
	clientDataSigner, err := clientdata.NewSigner(&cfg.FeatureGates, &cfg.ClientData)
	if err != nil {
		return nil, fmt.Errorf("failed to create client data factory: %w", err)
	}
	ops = append(ops, extauthz.WithClientDataSigner(clientDataSigner))

	if clientDataSigner.Enabled() {
		slogctx.Info(ctx, "Using client data with signing key", "id", clientDataSigner.SigningKeyID())
	} else {
		slogctx.Info(ctx, "Using client data has been disabled")
	}

	// Load all Cedar policy files from the policy path
	slogctx.Info(ctx, "Handling cedar policies", "cedar", cfg.Cedar)
	pe, err := cedarpolicy.NewEngine(cedarpolicy.WithPath(cfg.Cedar.PolicyPath))
	if err != nil {
		return nil, fmt.Errorf("failed to create the policy engine: %w", err)
	}
	ops = append(ops, extauthz.WithPolicyEngine(pe))

	// Load the trusted subjects
	subjects, err := loadTrustedSubjects(cfg.MTLS.TrustedSubjectsYaml)
	if err != nil {
		return nil, fmt.Errorf("failed to load trusted subjects: %w", err)
	}
	if len(cfg.JWT.IssuerClaimKeys) == 0 {
		slogctx.Warn(ctx, "JWT configuration doesn't have the issuer claims keys; Use the default values: [iss].")
		cfg.JWT.IssuerClaimKeys = jwthandler.DefaultIssuerClaims
	}
	ops = append(ops, extauthz.WithTrustedSubjects(subjects))

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
	ops = append(ops, extauthz.WithJWTHandler(hdl))

	// Create the ExtAuthZ server
	srv, err := extauthz.NewServer(ops...)
	if err != nil {
		return nil, fmt.Errorf("failed to create the ExtAuthZ server: %w", err)
	}

	return srv, nil
}
