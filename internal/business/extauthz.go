package business

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/openkcm/extauthz/internal/config"
	"github.com/openkcm/extauthz/internal/extauthz"
	"github.com/openkcm/extauthz/internal/jwthandler"
	"github.com/openkcm/extauthz/internal/policy"
	"github.com/openkcm/extauthz/internal/signing"
)

func createExtAuthZServer(ctx context.Context, cfg *config.Config) (*extauthz.Server, error) {
	// Load all Cedar policy files from the policy path
	pe, err := policy.NewEngine(policy.WithPath(cfg.PolicyPath))
	if err != nil {
		return nil, fmt.Errorf("failed to create the policy engine: %w", err)
	}
	// Load the trusted subjects
	subjects, err := loadTrustedSubjects(cfg.MTLS.TrustedSubjectsYaml)
	if err != nil {
		return nil, fmt.Errorf("failed to load trusted subjects: %w", err)
	}
	// parse the JWT operation mode
	var jwtOperationMode jwthandler.JWTOperationMode
	switch cfg.JWT.OperationMode {
	case config.JWTOperationModeSapias:
		jwtOperationMode = jwthandler.SAPIAS
	case config.JWTOperationModeDefault, "":
		jwtOperationMode = jwthandler.DefaultMode
	default:
		return nil, fmt.Errorf("invalid JWT operation mode: %s", cfg.JWT.OperationMode)
	}
	// Create the JWT handler
	hdl, err := jwthandler.NewHandler(
		jwthandler.WithOperationMode(jwtOperationMode),
		jwthandler.WithK8sJWTProviders(true,
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
	if cfg.ClientData.SigningKeyRefreshIntervalS > 0 {
		opts = append(opts, signing.WithRefreshInterval(time.Second*time.Duration(cfg.ClientData.SigningKeyRefreshIntervalS)))
	}
	signingKey, err := signing.NewKey(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create signing key: %w", err)
	}
	go func() {
		if err := signingKey.ServePublicKey(ctx, cfg.ClientData.PublicKeyAddress); err != nil {
			slog.Error("failed to serve public key", "error", err)
		}
	}()

	// Create the ExtAuthZ server
	srv, err := extauthz.NewServer(signingKey.Private,
		extauthz.WithPolicyEngine(pe),
		extauthz.WithJWTHandler(hdl),
		extauthz.WithTrustedSubjects(subjects),
		extauthz.WithEnrichHeaderWithRegion(cfg.ClientData.WithRegion),
		extauthz.WithEnrichHeaderWithType(cfg.ClientData.WithType),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create the ExtAuthZ server: %w", err)
	}
	return srv, nil
}
