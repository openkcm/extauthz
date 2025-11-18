package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewProviderSource(t *testing.T) {
	t.Run("no panic with nil options", func(t *testing.T) {
		assert.NotPanics(t, func() {
			//nolint:errcheck
			NewProviderSource(nil)
		})
	})
}
