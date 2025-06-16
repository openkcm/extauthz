package main_test

import (
	"testing"

	"github.com/gruntwork-io/terratest/modules/helm"
	"github.com/gruntwork-io/terratest/modules/k8s"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/autoscaling/v2"
)

func TestHorizontalPodAutoscaler(t *testing.T) {
	t.Parallel()

	// Arrange
	yamlFile := "templates/hpa.yaml"

	// create the test cases
	tests := []struct {
		name      string
		opts      *helm.Options
		wantError bool
		testFunc  func(t *testing.T, resource *corev1.HorizontalPodAutoscaler)
	}{
		{
			name: "default values",
			opts: &helm.Options{
				SetValues: map[string]string{
					"autoscaling.enabled": "true",
				},
			},
			wantError: false,
			testFunc: func(t *testing.T, resource *corev1.HorizontalPodAutoscaler) {
				require.Equal(t, appName, resource.Name)
				require.Equal(t, "default", resource.Namespace)
				require.Equal(t, 1, int(*resource.Spec.MinReplicas))
				require.Equal(t, 100, int(resource.Spec.MaxReplicas))
				require.Equal(t, "cpu", string(resource.Spec.Metrics[0].Resource.Name))
				require.Equal(t, 80, int(*resource.Spec.Metrics[0].Resource.Target.AverageUtilization))
				require.Equal(t, "memory", string(resource.Spec.Metrics[1].Resource.Name))
				require.Equal(t, 80, int(*resource.Spec.Metrics[1].Resource.Target.AverageUtilization))
			},
		}, {
			name: "custom values",
			opts: &helm.Options{
				SetValues: map[string]string{
					"autoscaling.enabled":                           "true",
					"autoscaling.minReplicas":                       "2",
					"autoscaling.maxReplicas":                       "5",
					"autoscaling.targetCPUUtilizationPercentage":    "70",
					"autoscaling.targetMemoryUtilizationPercentage": "70",
				},
				KubectlOptions: k8s.NewKubectlOptions("", "", "foo"),
			},
			wantError: false,
			testFunc: func(t *testing.T, resource *corev1.HorizontalPodAutoscaler) {
				require.Equal(t, appName, resource.Name)
				require.Equal(t, "foo", resource.Namespace)
				require.Equal(t, 2, int(*resource.Spec.MinReplicas))
				require.Equal(t, 5, int(resource.Spec.MaxReplicas))
				require.Equal(t, "cpu", string(resource.Spec.Metrics[0].Resource.Name))
				require.Equal(t, 70, int(*resource.Spec.Metrics[0].Resource.Target.AverageUtilization))
				require.Equal(t, "memory", string(resource.Spec.Metrics[1].Resource.Name))
				require.Equal(t, 70, int(*resource.Spec.Metrics[1].Resource.Target.AverageUtilization))
			},
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
			var resource corev1.HorizontalPodAutoscaler
			helm.UnmarshalK8SYaml(t, got, &resource)
			tc.testFunc(t, &resource)
		})
	}
}
