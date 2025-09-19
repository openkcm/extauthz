package sessioncache

import (
	"context"

	"github.com/valkey-io/valkey-go"

	"github.com/openkcm/extauthz/internal/extauthz"
)

const (
	SessionPrefix  = "sess_"        // Prefix for session keys in the cache.
	KeyIDToken     = "id_token"     // Field name for the ID token in the session hash.
	KeyAccessToken = "access_token" // Field name for the access token in the session hash.
)

type Cache struct {
	valkeyClient valkey.Client
}

var _ extauthz.SessionCache = &Cache{}

// Option is used to configure a session cache.
type Option func(*Cache) error

func WithValkeyClient(valkeyClient valkey.Client) Option {
	return func(sessionCache *Cache) error {
		sessionCache.valkeyClient = valkeyClient
		return nil
	}
}

// New creates a new session cache and applies the given options.
func New(opts ...Option) (*Cache, error) {
	sessionCache := &Cache{}
	for _, opt := range opts {
		err := opt(sessionCache)
		if err != nil {
			return nil, err
		}
	}
	return sessionCache, nil
}

func (v *Cache) Get(ctx context.Context, sessionID string) (*extauthz.Session, bool) {
	if v.valkeyClient != nil {
		return v.getFromValkey(ctx, sessionID)
	}
	return nil, false
}

func (v *Cache) getFromValkey(ctx context.Context, sessionID string) (*extauthz.Session, bool) {
	hm, err := v.valkeyClient.Do(ctx, v.valkeyClient.B().
		Hmget().
		Key(SessionPrefix+sessionID).
		Field(KeyIDToken).
		Build()).AsStrMap()
	if err != nil {
		return nil, false
	}

	sess := &extauthz.Session{
		IDToken: hm[KeyIDToken],
	}

	return sess, false
}
