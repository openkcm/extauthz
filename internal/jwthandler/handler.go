// Package jwthandler implements JWT token handling in a multi-tenant environment.
// For this a Handler is created, which holds the Providers for validating tokens.
// You can either register providers in a static manner, or define them as
// JWTProvider definition in kubernetes.
package jwthandler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/patrickmn/go-cache"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	DefaultIssuerClaims = []string{"iss"}
)

// Handler tracks the set of identity providers to support multi tenancy.
type Handler struct {
	issuerClaimKeys              []string
	k8sJWTProvidersEnabled       bool
	k8sJWTProvidersCRDAPIGroup   string
	k8sJWTProvidersCRDAPIVersion string
	k8sJWTProvidersCRDName       string
	k8sJWTProvidersCRDNamespace  string

	// cache the providers by issuer
	cache           *cache.Cache // map[string]*Provider or introspection
	expiration      time.Duration
	cleanupInterval time.Duration
}

// HandlerOption is used to configure a handler.
type HandlerOption func(*Handler) error

// WithIssuerClaimKeys configures the behavior of a certain provider.
func WithIssuerClaimKeys(issuerClaimKeys ...string) HandlerOption {
	return func(handler *Handler) error {
		handler.issuerClaimKeys = issuerClaimKeys
		return nil
	}
}

// WithProvider registers the given provider.
func WithProvider(provider *Provider) HandlerOption {
	return func(handler *Handler) error {
		if provider == nil {
			return errors.New("provider must not be nil")
		}
		handler.RegisterProvider(provider)
		return nil
	}
}

// WithK8sJWTProviders enables the use of k8s custom resource definitions
// for JWT providers.
func WithK8sJWTProviders(enabled bool, crdAPIGroup, crdAPIVersion, crdName, crdNamespace string) HandlerOption {
	return func(handler *Handler) error {
		slog.Debug("Using k8s JWT providers", "enabled", enabled, "apiGroup", crdAPIGroup, "apiVersion", crdAPIVersion, "name", crdName, "namespace", crdNamespace)
		handler.k8sJWTProvidersEnabled = enabled
		handler.k8sJWTProvidersCRDAPIGroup = crdAPIGroup
		handler.k8sJWTProvidersCRDAPIVersion = crdAPIVersion
		handler.k8sJWTProvidersCRDName = crdName
		handler.k8sJWTProvidersCRDNamespace = crdNamespace
		handler.cache = cache.New(handler.expiration, handler.cleanupInterval)
		return nil
	}
}

// WithProviderCacheExpiration configures the expiration of cached providers.
func WithProviderCacheExpiration(expiration, cleanup time.Duration) HandlerOption {
	return func(handler *Handler) error {
		handler.expiration = expiration
		handler.cleanupInterval = cleanup
		handler.cache = cache.New(expiration, cleanup)
		return nil
	}
}

// NewHandler creates a new handler and applies the given options.
func NewHandler(opts ...HandlerOption) (*Handler, error) {
	handler := &Handler{
		issuerClaimKeys: DefaultIssuerClaims,
		cache:           cache.New(30*time.Second, 10*time.Minute),
	}
	for _, opt := range opts {
		if err := opt(handler); err != nil {
			return nil, err
		}
	}
	return handler, nil
}

// RegisterProvider registers a provider with the handler.
func (handler *Handler) RegisterProvider(provider *Provider) {
	handler.cache.Set(provider.issuerURL.Host, provider, cache.DefaultExpiration)
}

func (handler *Handler) ParseAndValidate(ctx context.Context, rawToken string, userclaims any, allowIntrospectCache bool) error {
	// parse the token - at the moment we only support RS256
	token, err := jwt.ParseSigned(rawToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return errors.Join(ErrInvalidToken, err)
	}

	// parse the claims without verification
	claims := make(map[string]any)
	if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return errors.Join(ErrInvalidToken, err)
	}

	// check the issuer to find the right provider
	issuer := extractFromClaims(claims, handler.issuerClaimKeys...)
	//if handler.issuerClaimKeys == SAPIAS {
	//	issuer, _ = claims["ias_iss"].(string)
	//}
	if issuer == "" { // in case its empty
		return errors.Join(ErrInvalidToken, errors.New("missing iss in token claims"))
	}
	//if issuer == "" {
	//	issuer, _ = claims["iss"].(string)
	//
	//}
	issuerURL, err := url.Parse(issuer)
	if err != nil {
		return errors.Join(ErrInvalidToken, err)
	}
	if issuerURL.Scheme != "https" {
		return errors.Join(ErrInvalidToken, fmt.Errorf("invalid issuer scheme %s", issuerURL.Scheme))
	}

	// let the handler lookup the identity provider for the issuer host
	provider, err := handler.ProviderFor(issuerURL.Host)
	if err != nil {
		return errors.Join(ErrNoProvider, err)
	}

	// read the key ID from the token headers
	// Not sure why there are multiple headers, take the first one with key ID
	var keyID string
	for _, header := range token.Headers {
		if header.KeyID != "" {
			keyID = header.KeyID
			break
		}
	}
	if keyID == "" {
		return errors.Join(ErrInvalidToken, errors.New("missing kid in token header"))
	}

	// let the provider lookup the key for the key ID
	key, err := provider.SigningKeyFor(ctx, keyID)
	if err != nil {
		return errors.Join(ErrInvalidToken, err)
	}

	// check the signature and read the claims
	standardClaims := jwt.Claims{}
	if err := token.Claims(*key, &standardClaims, userclaims); err != nil {
		return errors.Join(ErrInvalidToken, err)
	}

	// verify the expiry and not before
	if standardClaims.Expiry == nil {
		return errors.Join(ErrInvalidToken, errors.New("missing exp in token claims"))
	}
	if err = standardClaims.Validate(jwt.Expected{
		Time: time.Now(),
	}); err != nil {
		return errors.Join(ErrInvalidToken, err)
	}

	// verify the audience if any
	if len(provider.audiences) > 0 {
		if err = standardClaims.Validate(jwt.Expected{
			AnyAudience: provider.audiences,
		}); err != nil {
			return errors.Join(ErrInvalidToken, err)
		}
	}

	// Verify if token is not revoked
	intr, err := handler.introspect(ctx, provider, rawToken, allowIntrospectCache)
	if err != nil {
		return fmt.Errorf("introspecting token: %w", err)
	}

	if !intr.Active {
		return ErrInvalidToken
	}

	return nil
}

// ProviderFor returns the provider for the given issuer. It either looks up the
// provider in the internal cache or queries the k8s cluster for the provider.
func (handler *Handler) ProviderFor(issuer string) (*Provider, error) {
	// check the cache first
	if providerInterface, found := handler.cache.Get(issuer); found {
		if key, ok := providerInterface.(*Provider); ok {
			return key, nil
		}
	}
	slog.Info("Provider cache miss", "issuer", issuer)

	// if enabled, create a new provider from k8s JWTProvider definition if any
	if handler.k8sJWTProvidersEnabled {
		k8sRestClient, err := handler.k8sRestClient()
		if err != nil {
			return nil, err
		}
		p, err := handler.k8sJWTProviderFor(k8sRestClient, issuer)
		if err != nil {
			return nil, err
		}
		// Cache the item. Constant `cache.DefaultExpiration` means
		// that this item does not have a custom expiration, but uses
		// the configured expiration of the cache.
		// https://pkg.go.dev/github.com/patrickmn/go-cache#Cache.Set
		handler.cache.Set(issuer, p, cache.DefaultExpiration)
		return p, nil
	}

	return nil, errors.Join(ErrNoProvider, fmt.Errorf("no provider found for issuer %s", issuer))
}

// introspect a JWT token.
func (handler *Handler) introspect(ctx context.Context, provider *Provider, rawToken string, allowCache bool) (introspection, error) {
	cacheKey := "introspect_" + "rawToken"
	if allowCache {
		cache, ok := handler.cache.Get(cacheKey)
		if ok {
			//nolint:forcetypeassert
			return cache.(introspection), nil
		}
	}

	intr, err := provider.introspect(ctx, rawToken)
	if err != nil {
		return intr, fmt.Errorf("introspecting token: %w", err)
	}

	handler.cache.Set(cacheKey, intr, 0)
	return intr, nil
}

type RemoteJWKS struct {
	URI string `json:"uri"`
}

type Spec struct {
	Name       string     `json:"name"`
	Issuer     string     `json:"issuer"`
	Audiences  []string   `json:"audiences,omitempty"`
	RemoteJwks RemoteJWKS `json:"remoteJwks,omitempty"`
}

type JWTProvider struct {
	Spec Spec `json:"spec"`
}

type JWTProviderResult struct {
	Items []JWTProvider `json:"items"`
}

func (handler *Handler) k8sRestClient() (rest.Interface, error) {
	// read the k8s config
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to read k8s config: %w", err)
	}

	// create the k8s clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s clientset: %w", err)
	}

	return clientset.RESTClient(), nil
}

// k8sJWTProviderFor queries the k8s cluster for JWT providers.
func (handler *Handler) k8sJWTProviderFor(k8sRestClient rest.Interface, issuer string) (*Provider, error) {
	slog.Debug("Querying k8s for JWT provider", "issuer", issuer)
	// query the jwtproviders
	result, err := k8sRestClient.Get().
		AbsPath(fmt.Sprintf("/apis/%s/%s",
			handler.k8sJWTProvidersCRDAPIGroup,
			handler.k8sJWTProvidersCRDAPIVersion,
		)).
		Namespace(handler.k8sJWTProvidersCRDNamespace).
		Resource(handler.k8sJWTProvidersCRDName).
		DoRaw(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to query jwtproviders: %w", err)
	}
	rawProviders := JWTProviderResult{}
	if err = json.Unmarshal(result, &rawProviders); err != nil {
		return nil, fmt.Errorf("failed to unmarshal jwtproviders: %w", err)
	}

	// find the right JWTProvider definition, create a new provider from it, cache and return it
	slog.Debug("Found k8s JWT providers", "count", len(rawProviders.Items))
	for _, provider := range rawProviders.Items {
		slog.Debug("Checking k8s JWT provider", "name", provider.Spec.Name, "issuer", provider.Spec.Issuer)
		// parse the issuer URL
		issuerURL, err := url.Parse(provider.Spec.Issuer)
		if err != nil {
			slog.Error("failed to parse issuer URL", "error", err)
			continue
		}

		// skip if the issuer does not match
		if issuerURL.Host != issuer {
			continue
		}

		var opts []ProviderOption

		// parse the JWKS URI if any
		if provider.Spec.RemoteJwks.URI != "" {
			jwksURI, err := url.Parse(provider.Spec.RemoteJwks.URI)
			if err != nil {
				slog.Error("failed to parse JWKS URI", "JWKSURI", provider.Spec.RemoteJwks.URI, "error", err)
				continue
			}
			opts = append(opts, WithCustomJWKSURI(jwksURI))
		}

		// create and return the provider
		p, err := NewProvider(issuerURL, provider.Spec.Audiences, opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to create provider: %w", err)
		}
		return p, nil
	}

	return nil, errors.Join(ErrNoProvider, fmt.Errorf("no provider found for issuer %s", issuer))
}

func extractFromClaims(claims map[string]any, keys ...string) string {
	for _, key := range keys {
		if val, ok := claims[key]; ok {
			return val.(string)
		}
	}
	return ""
}
