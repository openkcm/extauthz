package business

import (
	"context"
	"fmt"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/extauthz/internal/config"
	"github.com/openkcm/extauthz/internal/extauthz"
	"github.com/openkcm/extauthz/internal/jwthandler"
	"github.com/openkcm/extauthz/internal/policy"
	"github.com/openkcm/extauthz/internal/signing"
)

func createExtAuthZServer(ctx context.Context, cfg *config.Config) (*extauthz.Server, error) {
	// Load all Cedar policy files from the policy path
	slogctx.Info(ctx, "Handling cedar policies", "cedar", cfg.Cedar)

	pe, err := policy.NewEngine(policy.WithPath(cfg.Cedar.PolicyPath))
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
	// Create signing key and serve the public key
	opts := []signing.Option{}
	if cfg.CDKSServer.SigningKeyRefreshInterval > 0 {
		opts = append(opts, signing.WithRefreshInterval(cfg.CDKSServer.SigningKeyRefreshInterval))
	}

	signingKey, err := signing.NewKey(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create signing key: %w", err)
	}

	go func() {
		err := signingKey.ServePublicKey(ctx, cfg.CDKSServer.Address)
		if err != nil {
			slogctx.Error(ctx, "failed to serve public key", "error", err)
		}
	}()

	// Create the ExtAuthZ server
	srv, err := extauthz.NewServer(signingKey.Private,
		extauthz.WithPolicyEngine(pe),
		extauthz.WithJWTHandler(hdl),
		extauthz.WithTrustedSubjects(subjects),
		extauthz.WithFeatureGates(&cfg.FeatureGates),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create the ExtAuthZ server: %w", err)
	}

	return srv, nil
}
