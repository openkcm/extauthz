//go:build helmtests

package main_test

import (
	"fmt"
	"os"
	"testing"
)

const (
	path    = "../../charts/extauthz"
	appName = "extauthz"
)

// This file defines common constants used across all unit tests.
// The path points to the Helm chart directory, and appName is the release name used in tests.

// TestMain makes helm template render into the namespace "default", which the tests expect
// when they do not pass --namespace. Without HELM_NAMESPACE, helm takes the namespace of the
// current kubeconfig context.
func TestMain(m *testing.M) {
	if os.Getenv("HELM_NAMESPACE") == "" {
		err := os.Setenv("HELM_NAMESPACE", "default")
		if err != nil {
			fmt.Fprintln(os.Stderr, "setting HELM_NAMESPACE:", err)
			os.Exit(1)
		}
	}

	os.Exit(m.Run())
}
