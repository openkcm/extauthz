package business

import (
	"context"
	"fmt"
	"net/url"

	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/openkcm/common-sdk/pkg/commongrpc"
	"github.com/valkey-io/valkey-go"

	sessrepo "github.com/openkcm/session-manager/pkg/session/valkey"
	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/extauthz/internal/clientdata"
	"github.com/openkcm/extauthz/internal/config"
	"github.com/openkcm/extauthz/internal/extauthz"
	"github.com/openkcm/extauthz/internal/oidc"
	"github.com/openkcm/extauthz/internal/policies/cedarpolicy"
)

func createExtAuthZServer(ctx context.Context, cfg *config.Config) (*extauthz.Server, error) {
	// prepare the options for the server
	opts := []extauthz.ServerOption{
		extauthz.WithFeatureGates(&cfg.FeatureGates),
	}

	// Load the private key for signing the client data
	clientDataSigner, err := createClientDataSigner(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create client data signer: %w", err)
	}
	opts = append(opts, extauthz.WithClientDataSigner(clientDataSigner))

	// Load all Cedar policy files from the policy path
	slogctx.Info(ctx, "Handling cedar policies", "cedar", cfg.Cedar)
	pe, err := cedarpolicy.NewEngine(cedarpolicy.WithPath(cfg.Cedar.PolicyPath))
	if err != nil {
		return nil, fmt.Errorf("failed to create the policy engine: %w", err)
	}
	opts = append(opts, extauthz.WithPolicyEngine(pe))

	// Load the trusted subjects
	subjects, err := loadTrustedSubjects(cfg.MTLS.TrustedSubjectsYaml)
	if err != nil {
		return nil, fmt.Errorf("failed to load trusted subjects: %w", err)
	}
	opts = append(opts, extauthz.WithTrustedSubjects(subjects))

	// Create the OIDC handler
	oidcHandler, err := createOIDCHandler(ctx, &cfg.JWT, &cfg.FeatureGates)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC handler: %w", err)
	}
	opts = append(opts, extauthz.WithOIDCHandler(oidcHandler))

	// Create the session cache
	if cfg.SessionCache.Enabled {
		sessionCache, err := createValkeySessionCache(ctx, &cfg.SessionCache.Valkey)
		if err != nil {
			return nil, fmt.Errorf("failed to create Valkey session cache: %w", err)
		}
		opts = append(opts, extauthz.WithSessionCache(sessionCache))
	}
	if cfg.SessionCache.CMKPathPrefix != "" {
		slogctx.Info(ctx, "Using CMK path prefix for session cache", "prefix", cfg.SessionCache.CMKPathPrefix)
		opts = append(opts, extauthz.WithCMKPathPrefix(cfg.SessionCache.CMKPathPrefix))
	}

	// Create the ExtAuthZ server
	srv, err := extauthz.NewServer(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create the ExtAuthZ server: %w", err)
	}
	return srv, nil
}

func createClientDataSigner(ctx context.Context, cfg *config.Config) (*clientdata.Signer, error) {
	clientDataSigner, err := clientdata.NewSigner(&cfg.FeatureGates, &cfg.ClientData)
	if err != nil {
		return nil, fmt.Errorf("failed to create client data factory: %w", err)
	}
	if clientDataSigner.Enabled() {
		slogctx.Info(ctx, "Using client data with signing key", "id", clientDataSigner.SigningKeyID())
	} else {
		slogctx.Info(ctx, "Using client data has been disabled")
	}
	return clientDataSigner, nil
}

func createOIDCHandler(ctx context.Context, cfg *config.JWT, fg *commoncfg.FeatureGates) (*oidc.Handler, error) {
	opts := make([]oidc.HandlerOption, 0, 3+len(cfg.Providers))
	opts = append(opts, oidc.WithFeatureGates(fg))
	if len(cfg.IssuerClaimKeys) == 0 {
		slogctx.Warn(ctx, "JWT configuration doesn't have the issuer claims keys; Use the default values: [iss].")
		cfg.IssuerClaimKeys = oidc.DefaultIssuerClaims
	}
	opts = append(opts, oidc.WithIssuerClaimKeys(cfg.IssuerClaimKeys...))

	// add list of providers from configuration
	for _, p := range cfg.Providers {
		oidcProvider, err := createOIDCProvider(ctx, &p)
		if err != nil {
			return nil, fmt.Errorf("failed to create the OIDC provider: %w", err)
		}
		opts = append(opts, oidc.WithStaticProvider(oidcProvider))
	}

	// setup the K8SProviderRef to load providers based on the k8s JWTProvider CRD
	opts = append(opts, oidc.WithK8SJWTProviderRef(cfg.K8SProviderRef))

	// add provider source (if any)
	if cfg.ProviderSource.Enabled {
		providerSource, err := createOIDCProviderSource(ctx, &cfg.ProviderSource)
		if err != nil {
			return nil, fmt.Errorf("failed to create OIDC provider source: %w", err)
		}
		opts = append(opts, oidc.WithProviderClient(providerSource))
	}

	// create the handler
	hdl, err := oidc.NewHandler(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create the OIDC handler: %w", err)
	}
	return hdl, nil
}

func createOIDCProvider(ctx context.Context, cfg *config.Provider) (*oidc.Provider, error) {
	slogctx.Info(ctx, "Using static OIDC provider",
		"issuer", cfg.Issuer,
		"audiences", cfg.Audiences,
		"jwksURI", cfg.JwksURI,
		"introspectionEndpoint", cfg.IntrospectionEndpoint,
	)

	issuerURL, err := url.Parse(cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer URL %q: %w", cfg.Issuer, err)
	}

	oidcProvider, err := oidc.NewProvider(issuerURL, cfg.Audiences,
		oidc.WithRawJWKSURI(cfg.JwksURI),
		oidc.WithRawIntrospectTokenURL(cfg.IntrospectionEndpoint),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create the oidc provider: %w", err)
	}

	err = oidcProvider.RefreshConfiguration(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh the provider configuration: %w", err)
	}

	return oidcProvider, nil
}

func createOIDCProviderSource(ctx context.Context, cfg *commoncfg.GRPCClient) (*oidc.ProviderSource, error) {
	slogctx.Info(ctx, "Using OIDC provider source", "address", cfg.Address)

	// create the gRPC connection to the provider source
	grpcConn, err := commongrpc.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection to OIDC provider source: %w", err)
	}

	pc, err := oidc.NewProviderSource(oidc.WithGRPCConn(grpcConn))
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider source client: %w", err)
	}

	return pc, nil
}

func createValkeySessionCache(ctx context.Context, cfg *config.Valkey) (*sessrepo.Repository, error) {
	valkeyHost, err := commoncfg.LoadValueFromSourceRef(cfg.Host)
	if err != nil {
		return nil, fmt.Errorf("loading valkey host: %w", err)
	}

	valkeyUsername, err := commoncfg.LoadValueFromSourceRef(cfg.User)
	if err != nil {
		return nil, fmt.Errorf("loading valkey username: %w", err)
	}

	valkeyPassword, err := commoncfg.LoadValueFromSourceRef(cfg.Password)
	if err != nil {
		return nil, fmt.Errorf("loading valkey password: %w", err)
	}

	slogctx.Info(ctx, "Using Valkey for session cache", "address", string(valkeyHost), "user", string(valkeyUsername))
	valkeyClient, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{string(valkeyHost)},
		Username:    string(valkeyUsername),
		Password:    string(valkeyPassword),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create the Valkey client: %w", err)
	}

	return sessrepo.NewRepository(valkeyClient, cfg.Prefix), nil
}
