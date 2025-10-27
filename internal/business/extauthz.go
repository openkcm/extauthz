package business

import (
	"context"
	"fmt"
	"net/url"

	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/openkcm/common-sdk/pkg/commongrpc"
	"github.com/valkey-io/valkey-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

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
	oidcHandler, err := createOIDCHandler(ctx, &cfg.JWT)
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

func transportCredentialsFromSecretRef(secref *commoncfg.SecretRef) (credentials.TransportCredentials, error) {
	switch secref.Type {
	case commoncfg.InsecureSecretType:
		return insecure.NewCredentials(), nil
	case commoncfg.MTLSSecretType:
		tlsConfig, err := commoncfg.LoadMTLSConfig(&secref.MTLS)
		if err != nil {
			return nil, err
		}
		return credentials.NewTLS(tlsConfig), nil
	}
	return nil, fmt.Errorf("invalid secret type: %s", secref.Type)
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

func createOIDCHandler(ctx context.Context, cfg *config.JWT) (*oidc.Handler, error) {
	opts := make([]oidc.HandlerOption, 0, 2+len(cfg.Providers))
	if len(cfg.IssuerClaimKeys) == 0 {
		slogctx.Warn(ctx, "JWT configuration doesn't have the issuer claims keys; Use the default values: [iss].")
		cfg.IssuerClaimKeys = oidc.DefaultIssuerClaims
	}
	opts = append(opts, oidc.WithIssuerClaimKeys(cfg.IssuerClaimKeys...))
	// add static providers (if any)
	for _, p := range cfg.Providers {
		oidcProvider, err := createOIDCProvider(ctx, &p)
		if err != nil {
			return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
		}
		opts = append(opts, oidc.WithProvider(oidcProvider))
	}
	// add provider source (if any)
	if cfg.ProviderSource != nil {
		providerSource, err := createOIDCProviderSource(ctx, cfg.ProviderSource)
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
	slogctx.Info(ctx, "Using static OIDC provider", "issuer", cfg.Issuer, "audiences", cfg.Audiences, "jwksURIs", cfg.JwksURIs)
	issuerURL, err := url.Parse(cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer URL %q: %w", cfg.Issuer, err)
	}
	var popts []oidc.ProviderOption
	oidcProvider, err := oidc.NewProvider(issuerURL, cfg.Audiences, popts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create static OIDC provider: %w", err)
	}
	return oidcProvider, nil
}

func createOIDCProviderSource(ctx context.Context, cfg *config.ProviderSource) (*oidc.ProviderSource, error) {
	slogctx.Info(ctx, "Using OIDC provider source", "address", cfg.Address)
	creds, err := transportCredentialsFromSecretRef(&cfg.SecretRef)
	if err != nil {
		return nil, fmt.Errorf("failed to create transport credentials: %w", err)
	}
	// create the gRPC connection to the provider source
	grpcConn, err := commongrpc.NewClient(&cfg.GRPCClient,
		grpc.WithTransportCredentials(creds),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
	}
	pc, err := oidc.NewProviderSource(oidc.WithGRPCConn(grpcConn))
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider client: %w", err)
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
