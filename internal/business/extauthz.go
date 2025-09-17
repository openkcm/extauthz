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
	extauthzServerOptions := []extauthz.ServerOption{
		extauthz.WithFeatureGates(&cfg.FeatureGates),
	}

	// Load the private key for signing the client data
	clientDataSigner, err := clientdata.NewSigner(&cfg.FeatureGates, &cfg.ClientData)
	if err != nil {
		return nil, fmt.Errorf("failed to create client data factory: %w", err)
	}
	extauthzServerOptions = append(extauthzServerOptions, extauthz.WithClientDataSigner(clientDataSigner))

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
	extauthzServerOptions = append(extauthzServerOptions, extauthz.WithPolicyEngine(pe))

	// Load the trusted subjects
	subjects, err := loadTrustedSubjects(cfg.MTLS.TrustedSubjectsYaml)
	if err != nil {
		return nil, fmt.Errorf("failed to load trusted subjects: %w", err)
	}
	if len(cfg.JWT.IssuerClaimKeys) == 0 {
		slogctx.Warn(ctx, "JWT configuration doesn't have the issuer claims keys; Use the default values: [iss].")
		cfg.JWT.IssuerClaimKeys = oidc.DefaultIssuerClaims
	}
	extauthzServerOptions = append(extauthzServerOptions, extauthz.WithTrustedSubjects(subjects))

	// Create the JWT handler
	opts := make([]oidc.HandlerOption, 0, 2+len(cfg.JWT.Providers))
	opts = append(opts, oidc.WithIssuerClaimKeys(cfg.JWT.IssuerClaimKeys...))
	// add static providers (if any)
	for _, p := range cfg.JWT.Providers {
		slogctx.Info(ctx, "Using static JWT provider", "issuer", p.Issuer, "audiences", p.Audiences, "jwksURIs", p.JwksURIs)
		issuerURL, err := url.Parse(p.Issuer)
		if err != nil {
			return nil, fmt.Errorf("failed to parse issuer URL %q: %w", p.Issuer, err)
		}
		var popts []oidc.ProviderOption
		p, err := oidc.NewProvider(issuerURL, p.Audiences, popts...)
		if err != nil {
			return nil, fmt.Errorf("failed to create static JWT provider: %w", err)
		}
		opts = append(opts, oidc.WithProvider(p))
	}
	// add provider source (if any)
	if cfg.JWT.ProviderSource != nil {
		slogctx.Info(ctx, "Using JWT provider source", "address", cfg.JWT.ProviderSource.Address)
		creds, err := transportCredentialsFromSecretRef(&cfg.JWT.ProviderSource.SecretRef)
		if err != nil {
			return nil, fmt.Errorf("failed to create transport credentials: %w", err)
		}
		// create the gRPC connection to the provider source
		grpcConn, err := commongrpc.NewClient(&cfg.JWT.ProviderSource.GRPCClient,
			grpc.WithTransportCredentials(creds),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
		}
		pc, err := oidc.NewProviderSource(oidc.WithGRPCConn(grpcConn))
		if err != nil {
			return nil, fmt.Errorf("failed to create OIDC provider client: %w", err)
		}
		opts = append(opts, oidc.WithProviderClient(pc))
	}
	// create the handler
	hdl, err := oidc.NewHandler(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create the JWT handler: %w", err)
	}
	extauthzServerOptions = append(extauthzServerOptions, extauthz.WithOIDCHandler(hdl))

	// Create the session cache (if any)
	if cfg.SessionCache.Valkey != nil {
		valkeyHost, err := commoncfg.LoadValueFromSourceRef(cfg.SessionCache.Valkey.Host)
		if err != nil {
			return nil, fmt.Errorf("loading valkey host: %w", err)
		}
		valkeyUsername, err := commoncfg.LoadValueFromSourceRef(cfg.SessionCache.Valkey.User)
		if err != nil {
			return nil, fmt.Errorf("loading valkey username: %w", err)
		}
		valkeyPassword, err := commoncfg.LoadValueFromSourceRef(cfg.SessionCache.Valkey.Password)
		if err != nil {
			return nil, fmt.Errorf("loading valkey password: %w", err)
		}
		slogctx.Info(ctx, "Using Valkey for session cache", "address", valkeyHost, "user", valkeyUsername)
		if err != nil {
			return nil, fmt.Errorf("failed to create transport credentials: %w", err)
		}
		valkeyClient, err := valkey.NewClient(valkey.ClientOption{
			InitAddress: []string{string(valkeyHost)},
			Username:    string(valkeyUsername),
			Password:    string(valkeyPassword),
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create the Valkey client: %w", err)
		}
		sessionCache := sessrepo.NewRepository(valkeyClient, cfg.SessionCache.Valkey.Prefix)
		extauthzServerOptions = append(extauthzServerOptions, extauthz.WithSessionCache(sessionCache))
	}

	// Create the ExtAuthZ server
	srv, err := extauthz.NewServer(extauthzServerOptions...)
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
