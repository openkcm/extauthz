package business

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/openkcm/common-sdk/pkg/commongrpc"
	"github.com/openkcm/common-sdk/pkg/commonhttp"
	"github.com/openkcm/common-sdk/pkg/oidc"
	"github.com/valkey-io/valkey-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	otlpaudit "github.com/openkcm/common-sdk/pkg/otlp/audit"
	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/extauthz/internal/auditqueue"
	"github.com/openkcm/extauthz/internal/clientdata"
	"github.com/openkcm/extauthz/internal/config"
	"github.com/openkcm/extauthz/internal/extauthz"
	"github.com/openkcm/extauthz/internal/handler"
	"github.com/openkcm/extauthz/internal/metric"
	"github.com/openkcm/extauthz/internal/oauth2client"
	"github.com/openkcm/extauthz/internal/policies/cedarpolicy"
	"github.com/openkcm/extauthz/internal/ratestore"
	"github.com/openkcm/extauthz/internal/session"
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

	var sessionManager *session.Manager
	// Create the session manager (if configured)
	if cfg.SessionManager.Enabled && len(cfg.SessionPathPrefixes) > 0 {
		sessionManager, err = createSessionManager(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create session manager: %w", err)
		}
		opts = append(opts, extauthz.WithSessionManager(sessionManager))
		slogctx.Info(ctx, "Using session paths", "paths", cfg.SessionPathPrefixes)
		opts = append(opts, extauthz.WithSessionPathPrefixes(cfg.SessionPathPrefixes))
	}

	// Create the OIDC handler
	oidcHandler, err := createOIDCHandler(ctx, sessionManager, &cfg.JWT, &cfg.FeatureGates)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC handler: %w", err)
	}
	opts = append(opts, extauthz.WithOIDCHandler(oidcHandler))

	csrfSecret, err := commoncfg.LoadValueFromSourceRef(cfg.CSRFSecret)
	if err != nil {
		return nil, fmt.Errorf("loading csrf secret: %w", err)
	}

	opts = append(opts, extauthz.WithCSRFSecret(csrfSecret))

	// The audit pipeline is only wired when audit delivery is configured (a
	// non-empty endpoint) or rate detection is enabled. Otherwise extauthz runs
	// with the no-op audit logger and rate store and starts no worker goroutines.
	//
	// NOTE: cfg.Audit cannot be compared against the zero value to detect
	// "configured", because commoncfg.Audit embeds an HTTPClient whose Timeout
	// carries a struct default (10s) that the config loader always applies. The
	// endpoint is the meaningful signal for whether audit delivery is wanted.
	auditConfigured := cfg.Audit.Endpoint != ""
	if auditConfigured || cfg.Valkey.RateDetection.Enabled {
		if auditConfigured {
			auditLogger, err := otlpaudit.NewLogger(&cfg.Audit)
			if err != nil {
				return nil, fmt.Errorf("creating audit logger: %w", err)
			}

			opts = append(opts, extauthz.WithAuditLogger(auditLogger))
		}

		metrics, err := metric.New(nil)
		if err != nil {
			return nil, fmt.Errorf("creating audit metrics: %w", err)
		}
		opts = append(opts, extauthz.WithMetrics(metrics))

		// Async dispatcher: keeps the Valkey round-trip and audit HTTP POST off
		// the Check() hot path.
		queue := auditqueue.New(auditqueue.Options{
			Metrics:         metrics,
			Size:            cfg.Valkey.RateDetection.QueueSize,
			Workers:         cfg.Valkey.RateDetection.Workers,
			DispatchTimeout: cfg.Valkey.RateDetection.DispatchTimeout,
		})
		opts = append(opts, extauthz.WithAuditQueue(queue))

		if cfg.Valkey.RateDetection.Enabled {
			rateStore, err := createRateStore(ctx, cfg)
			if err != nil {
				return nil, fmt.Errorf("creating rate store: %w", err)
			}
			opts = append(opts,
				extauthz.WithRateStore(rateStore),
				extauthz.WithCountUnknown(cfg.Valkey.RateDetection.CountUnknown),
			)
		}
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
		tlsConfig, err := tlsConfigFromSecretRef(secref)
		if err != nil {
			return nil, err
		}
		return credentials.NewTLS(tlsConfig), nil
	}
	return nil, fmt.Errorf("invalid secret type: %s", secref.Type)
}

// tlsConfigFromSecretRef returns the *tls.Config described by an mTLS SecretRef.
// It centralises the MTLSSecretType -> LoadMTLSConfig interpretation so callers
// needing a *tls.Config directly (the Valkey client) and callers needing gRPC
// transport credentials share one definition of how a SecretRef maps to TLS.
// Callers must check secref.Type == commoncfg.MTLSSecretType first.
func tlsConfigFromSecretRef(secref *commoncfg.SecretRef) (*tls.Config, error) {
	return commoncfg.LoadMTLSConfig(&secref.MTLS)
}

func createClientDataSigner(ctx context.Context, cfg *config.Config) (*clientdata.Signer, error) {
	clientDataSigner, err := clientdata.NewSigner(&cfg.FeatureGates, &cfg.ClientData)
	if err != nil {
		return nil, fmt.Errorf("failed to create client data factory: %w", err)
	}
	slogctx.Info(ctx, "Using client data reading the signing key from", "signingKeyFile", cfg.ClientData.SigningKeyIDFilePath)
	return clientDataSigner, nil
}

func createOIDCHandler(ctx context.Context, sessionManager *session.Manager, cfg *config.JWT, fg *commoncfg.FeatureGates) (*handler.OIDC, error) {
	opts := make([]handler.OIDCOption, 0, 3+len(cfg.Providers))
	opts = append(opts, handler.WithFeatureGates(fg))
	if len(cfg.IssuerClaimKeys) == 0 {
		slogctx.Warn(ctx, "JWT configuration doesn't have the issuer claims keys; Use the default values: [iss].")
		cfg.IssuerClaimKeys = oidc.DefaultIssuerClaims
	}
	opts = append(opts, handler.WithIssuerClaimKeys(cfg.IssuerClaimKeys...))
	// add static providers (if any)
	for _, p := range cfg.Providers {
		oidcProvider, err := createOIDCProvider(ctx, &cfg.HTTPClient, &p)
		if err != nil {
			return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
		}
		opts = append(opts, handler.WithStaticProvider(oidcProvider))
	}

	if sessionManager != nil {
		opts = append(opts, handler.WithSessionManager(sessionManager))
	}

	// create the handler
	hdl, err := handler.NewOIDC(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create the OIDC handler: %w", err)
	}
	return hdl, nil
}

func createOIDCProvider(ctx context.Context, httpClientCfg *commoncfg.HTTPClient, cfg *config.Provider) (*oidc.Provider, error) {
	slogctx.Info(ctx, "Using static OIDC provider",
		"issuer", cfg.Issuer,
		"issuerURI", cfg.IssuerURI,
		"jwksURI", cfg.JwksURI,
		"audiences", cfg.Audiences,
		"disableTokenIntrospection", cfg.DisableTokenIntrospection,
	)
	httpClient, err := commonhttp.NewHTTPClient(httpClientCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client for OIDC provider: %w", err)
	}
	oidcProvider, err := oidc.NewProvider(cfg.Issuer, cfg.Audiences,
		oidc.WithSecureHTTPClient(httpClient),
		oidc.WithCustomIssuerURI(cfg.IssuerURI),
		oidc.WithCustomJWKSURI(cfg.JwksURI),
		oidc.WithDisableTokenIntrospection(cfg.DisableTokenIntrospection),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create static OIDC provider: %w", err)
	}
	return oidcProvider, nil
}

func createSessionManager(ctx context.Context, cfg *config.Config) (*session.Manager, error) {
	slogctx.Info(ctx, "Using Session Manager", "address", cfg.SessionManager.Address)
	creds, err := transportCredentialsFromSecretRef(cfg.SessionManager.SecretRef)
	if err != nil {
		return nil, fmt.Errorf("failed to create transport credentials: %w", err)
	}
	// create the gRPC connection
	grpcConn, err := commongrpc.NewClient(&cfg.SessionManager, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
	}

	// Create the OAuth2 client builder from the JWT OAuth2 template configuration
	builder := oauth2client.NewBuilder(cfg.JWT.OAuth2)

	sm, err := session.NewManager(grpcConn,
		session.WithOAuth2ClientBuilder(builder),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create session manager: %w", err)
	}
	return sm, nil
}

// createRateStore builds a Valkey-backed rate store for unauthenticated-burst
// detection. Address/user/password are resolved from the configured SourceRefs;
// TLS follows the same SecretRef convention as the session manager.
func createRateStore(ctx context.Context, cfg *config.Config) (*ratestore.ValkeyStore, error) {
	vc := &cfg.Valkey

	address, err := commoncfg.LoadValueFromSourceRef(vc.Address)
	if err != nil {
		return nil, fmt.Errorf("loading valkey address: %w", err)
	}
	if len(address) == 0 {
		return nil, errors.New("valkey address must not be empty when rate detection is enabled")
	}

	clientOpt := valkey.ClientOption{
		InitAddress: []string{string(address)},
	}

	// User and password are optional: an unset SourceRef (empty Source) means
	// no credential, not an error, so an insecure/no-auth Valkey is supported.
	if vc.User.Source != "" {
		user, err := commoncfg.LoadValueFromSourceRef(vc.User)
		if err != nil {
			return nil, fmt.Errorf("loading valkey user: %w", err)
		}
		if len(user) > 0 {
			clientOpt.Username = string(user)
		}
	}

	if vc.Password.Source != "" {
		password, err := commoncfg.LoadValueFromSourceRef(vc.Password)
		if err != nil {
			return nil, fmt.Errorf("loading valkey password: %w", err)
		}
		if len(password) > 0 {
			clientOpt.Password = string(password)
		}
	}

	if vc.SecretRef.Type == commoncfg.MTLSSecretType {
		tlsConfig, err := tlsConfigFromSecretRef(&vc.SecretRef)
		if err != nil {
			return nil, fmt.Errorf("loading valkey mTLS config: %w", err)
		}
		clientOpt.TLSConfig = tlsConfig
	}

	client, err := valkey.NewClient(clientOpt)
	if err != nil {
		return nil, fmt.Errorf("creating valkey client: %w", err)
	}

	slogctx.Info(ctx, "Using Valkey rate store for unauthenticated-burst detection",
		"threshold", vc.RateDetection.Threshold,
		"window", vc.RateDetection.Window,
		"cooldown", vc.RateDetection.Cooldown,
	)

	store, err := ratestore.New(ratestore.Options{
		Client:    client,
		KeyPrefix: vc.Prefix,
		Threshold: vc.RateDetection.Threshold,
		Window:    vc.RateDetection.Window,
		Cooldown:  vc.RateDetection.Cooldown,
	})
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("creating valkey rate store: %w", err)
	}

	return store, nil
}
