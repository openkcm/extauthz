package business

import (
	"context"
	"testing"
	"time"

	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/extauthz/internal/config"
)

// TestCreateRateStore_EmptyAddress asserts rate detection refuses to build a
// store without a configured Valkey address rather than dialing an empty one.
func TestCreateRateStore_EmptyAddress(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{}
	cfg.Valkey.Address = commoncfg.SourceRef{Source: commoncfg.EmbeddedSourceValue, Value: ""}
	cfg.Valkey.RateDetection.Enabled = true

	_, err := createRateStore(context.Background(), cfg)
	require.ErrorContains(t, err, "valkey address must not be empty")
}

// TestCreateRateStore_AddressLoadError asserts a SourceRef that cannot be
// resolved surfaces as an error instead of a panic.
func TestCreateRateStore_AddressLoadError(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{}
	// An env source with an unset variable fails to load.
	cfg.Valkey.Address = commoncfg.SourceRef{Source: commoncfg.EnvSourceValue, Env: "EXTAUTHZ_TEST_UNSET_VALKEY_ADDR"}
	cfg.Valkey.RateDetection.Enabled = true

	_, err := createRateStore(context.Background(), cfg)
	require.ErrorContains(t, err, "loading valkey address")
}

// TestCreateRateStore_SentinelInvalidTopologyRefreshInterval asserts that the
// sentinel fields (MasterSet and TopologyRefreshInterval) are plumbed from the
// Valkey config into the valkey client's SentinelOption. A negative
// TopologyRefreshInterval is rejected eagerly by valkey.NewClient, but only on
// the sentinel path, which is taken only when MasterSet is set — so this error
// confirms both fields are actually wired through.
func TestCreateRateStore_SentinelInvalidTopologyRefreshInterval(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{}
	cfg.Valkey.Address = commoncfg.SourceRef{Source: commoncfg.EmbeddedSourceValue, Value: "localhost:26379"}
	cfg.Valkey.MasterSet = "mymaster"
	cfg.Valkey.TopologyRefreshInterval = -time.Second
	cfg.Valkey.RateDetection.Enabled = true

	_, err := createRateStore(context.Background(), cfg)
	require.ErrorContains(t, err, "creating valkey client")
	require.ErrorContains(t, err, "TopologyRefreshInterval")
}

func TestTLSConfigFromSecretRef(t *testing.T) {
	t.Parallel()

	// A non-mTLS secret ref is never passed to tlsConfigFromSecretRef by the
	// callers (they guard on MTLSSecretType), but an mTLS ref with no material
	// must surface a load error rather than panicking.
	ref := &commoncfg.SecretRef{Type: commoncfg.MTLSSecretType}
	_, err := tlsConfigFromSecretRef(ref)
	require.Error(t, err)
}
