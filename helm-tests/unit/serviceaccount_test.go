package main_test

import (
	"testing"

	"github.com/gruntwork-io/terratest/modules/helm"
	"github.com/gruntwork-io/terratest/modules/k8s"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
)

func TestServiceAccount(t *testing.T) {
	t.Parallel()

	// Arrange
	yamlFile := "templates/serviceaccount.yaml"

	// create the test cases
	tests := []struct {
		name      string
		opts      *helm.Options
		wantError bool
		testFunc  func(t *testing.T, resource *corev1.ServiceAccount)
	}{
		{
			name:      "default values",
			opts:      &helm.Options{},
			wantError: false,
			testFunc: func(t *testing.T, resource *corev1.ServiceAccount) {
				t.Helper()
				require.Equal(t, appName, resource.Name)
				require.Equal(t, "default", resource.Namespace)
				require.True(t, *resource.AutomountServiceAccountToken)
			},
		}, {
			name: "custom values",
			opts: &helm.Options{
				SetValues: map[string]string{
					"serviceAccount.automount": "false",
				},
				KubectlOptions: k8s.NewKubectlOptions("", "", "foo"),
			},
			wantError: false,
			testFunc: func(t *testing.T, resource *corev1.ServiceAccount) {
				t.Helper()
				require.Equal(t, appName, resource.Name)
				require.Equal(t, "foo", resource.Namespace)
				require.False(t, *resource.AutomountServiceAccountToken)
			},
		},
	}

	// run the tests
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Act
			got, err := helm.RenderTemplateE(t, tc.opts, path, appName, []string{yamlFile})

			// Assert
			if tc.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			var resource corev1.ServiceAccount
			helm.UnmarshalK8SYaml(t, got, &resource)
			tc.testFunc(t, &resource)
		})
	}
}
