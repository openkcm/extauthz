package main_test

import (
	"testing"

	"github.com/gruntwork-io/terratest/modules/helm"
	"github.com/gruntwork-io/terratest/modules/k8s"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
)

func TestService(t *testing.T) {
	t.Parallel()

	// Arrange
	yamlFile := "templates/service.yaml"

	// create the test cases
	tests := []struct {
		name      string
		opts      *helm.Options
		wantError bool
		testFunc  func(t *testing.T, resource *corev1.Service)
	}{
		{
			name:      "default values",
			opts:      &helm.Options{},
			wantError: false,
			testFunc: func(t *testing.T, resource *corev1.Service) {
				require.Equal(t, appName, resource.Name)
				require.Equal(t, "default", resource.Namespace)
				require.Equal(t, "ClusterIP", string(resource.Spec.Type))
				require.Equal(t, 9092, int(resource.Spec.Ports[0].Port))
				require.Equal(t, 9092, int(resource.Spec.Ports[0].TargetPort.IntVal))
				require.Equal(t, 8080, int(resource.Spec.Ports[1].Port))
				require.Equal(t, 8080, int(resource.Spec.Ports[1].TargetPort.IntVal))
			},
		}, {
			name: "custom values",
			opts: &helm.Options{
				SetValues: map[string]string{
					"service.type":                "NodePort",
					"service.ports[0].port":       "9093",
					"service.ports[0].targetPort": "9093",
					"service.ports[1].port":       "8081",
					"service.ports[1].targetPort": "8081",
				},
				KubectlOptions: k8s.NewKubectlOptions("", "", "foo"),
			},
			wantError: false,
			testFunc: func(t *testing.T, resource *corev1.Service) {
				require.Equal(t, appName, resource.Name)
				require.Equal(t, "foo", resource.Namespace)
				require.Equal(t, "NodePort", string(resource.Spec.Type))
				require.Equal(t, 9093, int(resource.Spec.Ports[0].Port))
				require.Equal(t, 9093, int(resource.Spec.Ports[0].TargetPort.IntVal))
				require.Equal(t, 8081, int(resource.Spec.Ports[1].Port))
				require.Equal(t, 8081, int(resource.Spec.Ports[1].TargetPort.IntVal))
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
			var resource corev1.Service
			helm.UnmarshalK8SYaml(t, got, &resource)
			tc.testFunc(t, &resource)
		})
	}
}
