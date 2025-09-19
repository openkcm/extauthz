package business

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/openkcm/common-sdk/pkg/commongrpc"
	"github.com/valkey-io/valkey-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/extauthz/internal/clientdata"
	"github.com/openkcm/extauthz/internal/config"
	"github.com/openkcm/extauthz/internal/extauthz"
	"github.com/openkcm/extauthz/internal/jwthandler"
	"github.com/openkcm/extauthz/internal/policies/cedarpolicy"
	"github.com/openkcm/extauthz/internal/sessioncache"
)

func createExtAuthZServer(ctx context.Context, cfg *config.Config) (*extauthz.Server, error) {
	// Load the private key for signing the client data
	clientDataFactory, err := clientdata.NewFactory(&cfg.FeatureGates, &cfg.ClientData)
	if err != nil {
		return nil, fmt.Errorf("failed to create client data factory: %w", err)
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
	opts := make([]jwthandler.HandlerOption, 0, 2+len(cfg.JWT.Providers))
	opts = append(opts, jwthandler.WithIssuerClaimKeys(cfg.JWT.IssuerClaimKeys...))
	// add static providers (if any)
	for _, p := range cfg.JWT.Providers {
		slogctx.Info(ctx, "Using static JWT provider", "issuer", p.Issuer, "audiences", p.Audiences, "jwksURIs", p.JwksURIs)
		issuerURL, err := url.Parse(p.Issuer)
		if err != nil {
			return nil, fmt.Errorf("failed to parse issuer URL %q: %w", p.Issuer, err)
		}
		var popts []jwthandler.ProviderOption
		p, err := jwthandler.NewProvider(issuerURL, p.Audiences, popts...)
		if err != nil {
			return nil, fmt.Errorf("failed to create static JWT provider: %w", err)
		}
		opts = append(opts, jwthandler.WithProvider(p))
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
		pc, err := jwthandler.NewProviderSource(jwthandler.WithGRPCConn(grpcConn))
		if err != nil {
			return nil, fmt.Errorf("failed to create OIDC provider client: %w", err)
		}
		opts = append(opts, jwthandler.WithProviderClient(pc))
	}
	// create the handler
	hdl, err := jwthandler.NewHandler(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create the JWT handler: %w", err)
	}

	// Create the session cache
	sessionCacheOpts := make([]sessioncache.Option, 0, 1)
	if cfg.SessionCache.Valkey != nil {
		slogctx.Info(ctx, "Using Valkey for session cache", "address", cfg.SessionCache.Valkey.InitAddress)
		username, password, err := usernamePasswordFromSecretRef(&cfg.SessionCache.Valkey.SecretRef)
		if err != nil {
			return nil, fmt.Errorf("failed to create transport credentials: %w", err)
		}
		valkeyClient, err := valkey.NewClient(valkey.ClientOption{
			InitAddress: cfg.SessionCache.Valkey.InitAddress,
			Username:    username,
			Password:    password,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create the Valkey client: %w", err)
		}
		sessionCacheOpts = append(sessionCacheOpts, sessioncache.WithValkeyClient(valkeyClient))
	} else {
		return nil, errors.New("no session cache configuration found")
	}
	sessionCache, err := sessioncache.New(sessionCacheOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create the session cache: %w", err)
	}

	// Create the ExtAuthZ server
	srv, err := extauthz.NewServer(
		extauthz.WithPolicyEngine(pe),
		extauthz.WithJWTHandler(hdl),
		extauthz.WithClientDataFactory(clientDataFactory),
		extauthz.WithTrustedSubjects(subjects),
		extauthz.WithFeatureGates(&cfg.FeatureGates),
		extauthz.WithSessionCache(sessionCache),
	)
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

func usernamePasswordFromSecretRef(secref *commoncfg.SecretRef) (string, string, error) {
	switch secref.Type {
	case commoncfg.InsecureSecretType:
		return "", "", nil
	case commoncfg.BasicSecretType:
		username, err := commoncfg.ExtractValueFromSourceRef(&secref.Basic.Username)
		if err != nil {
			return "", "", fmt.Errorf("failed to extract username: %w", err)
		}
		password, err := commoncfg.ExtractValueFromSourceRef(&secref.Basic.Password)
		if err != nil {
			return "", "", fmt.Errorf("failed to extract username: %w", err)
		}
		return string(username), string(password), nil
	}
	return "", "", fmt.Errorf("invalid secret type: %s", secref.Type)
}
