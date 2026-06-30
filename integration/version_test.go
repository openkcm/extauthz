//go:build integration

package integration_test

import (
	"os/exec"
	"testing"
)

func TestVersion(t *testing.T) {
	ctx := t.Context()
	// Arrange
	cmd := exec.CommandContext(ctx, "./"+binary, "-version")

	// Act
	err := cmd.Run()

	// Assert
	if err != nil {
		t.Errorf("failed to run %s -version: %v", binary, err)
	}
}
