package main_test

import (
	"testing"

	"github.com/gruntwork-io/terratest/modules/helm"
	"github.com/gruntwork-io/terratest/modules/k8s"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/policy/v1"
)

func TestPodDisruptionBudget(t *testing.T) {
	t.Parallel()

	// Arrange
	yamlFile := "templates/pdb.yaml"

	// create the test cases
	tests := []struct {
		name      string
		opts      *helm.Options
		wantError bool
		testFunc  func(t *testing.T, resource *corev1.PodDisruptionBudget)
	}{
		{
			name: "default values",
			opts: &helm.Options{
				SetValues: map[string]string{
					"pod.disruptionBudget.enabled": "true",
				},
			},
			wantError: false,
			testFunc: func(t *testing.T, resource *corev1.PodDisruptionBudget) {
				require.Equal(t, appName, resource.Name)
				require.Equal(t, "default", resource.Namespace)
				require.Equal(t, "1", resource.Spec.MinAvailable.String())
			},
		}, {
			name: "custom minAvailable",
			opts: &helm.Options{
				SetValues: map[string]string{
					"pod.disruptionBudget.enabled":      "true",
					"pod.disruptionBudget.minAvailable": "42",
				},
				KubectlOptions: k8s.NewKubectlOptions("", "", "foo"),
			},
			wantError: false,
			testFunc: func(t *testing.T, resource *corev1.PodDisruptionBudget) {
				require.Equal(t, appName, resource.Name)
				require.Equal(t, "foo", resource.Namespace)
				require.Equal(t, "42", resource.Spec.MinAvailable.String())
			},
		}, {
			name: "custom maxUnavailable",
			opts: &helm.Options{
				SetValues: map[string]string{
					"pod.disruptionBudget.enabled":        "true",
					"pod.disruptionBudget.maxUnavailable": "42",
				},
				KubectlOptions: k8s.NewKubectlOptions("", "", "foo"),
			},
			wantError: false,
			testFunc: func(t *testing.T, resource *corev1.PodDisruptionBudget) {
				require.Equal(t, appName, resource.Name)
				require.Equal(t, "foo", resource.Namespace)
				require.Equal(t, "42", resource.Spec.MaxUnavailable.String())
			},
		}, {
			name: "conflicting minAvailable + maxUnavailable",
			opts: &helm.Options{
				SetValues: map[string]string{
					"pod.disruptionBudget.enabled":        "true",
					"pod.disruptionBudget.minAvailable":   "41",
					"pod.disruptionBudget.maxUnavailable": "43",
				},
			},
			wantError: true,
		},
	}

	// run the tests
	for _, tc := range tests {
		tc := tc // capture range variable for parallel tests
		t.Run(tc.name, func(t *testing.T) {
			// Act
			got, err := helm.RenderTemplateE(t, tc.opts, path, appName, []string{yamlFile})

			// Assert
			if tc.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			var resource corev1.PodDisruptionBudget
			helm.UnmarshalK8SYaml(t, got, &resource)
			tc.testFunc(t, &resource)
		})
	}
}
