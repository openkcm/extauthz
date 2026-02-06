package main_test

import (
	"testing"

	"github.com/gruntwork-io/terratest/modules/helm"
	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/apps/v1"
)

func TestDeployment(t *testing.T) {
	t.Parallel()

	// Arrange
	yamlFile := "templates/deployment.yaml"

	// create the test cases
	tests := []struct {
		name      string
		opts      *helm.Options
		wantError bool
		testFunc  func(t *testing.T, resource *corev1.Deployment)
	}{
		{
			name: "default values",
			opts: &helm.Options{
				SetValues: map[string]string{},
			},
			wantError: false,
			testFunc: func(t *testing.T, resource *corev1.Deployment) {
				t.Helper()
				require.Equal(t, appName, resource.Name)
				require.Equal(t, "default", resource.Namespace)
				require.Equal(t, "registry-access", resource.Spec.Template.Spec.ImagePullSecrets[0].Name)
				require.Equal(t, appName, resource.Spec.Template.Spec.ServiceAccountName)
			},
		}, {
			name: "custom values",
			opts: &helm.Options{
				SetValues: map[string]string{
					"hpa.enabled":              "true",
					"hpa.minReplicas":          "3",
					"imagePullSecrets[0].name": "my-registry-access",
					"serviceAccount.name":      "my-extauthz",
				},
			},
			wantError: false,
			testFunc: func(t *testing.T, resource *corev1.Deployment) {
				t.Helper()
				require.Equal(t, appName, resource.Name)
				require.Equal(t, "default", resource.Namespace)
				require.Equal(t, 3, int(*resource.Spec.Replicas))
				require.Equal(t, "my-registry-access", resource.Spec.Template.Spec.ImagePullSecrets[0].Name)
				require.Equal(t, "my-extauthz", resource.Spec.Template.Spec.ServiceAccountName)
			},
		}, {
			name: "extraContainers",
			opts: &helm.Options{
				SetValues: map[string]string{
					"extraContainers[0].name":  "foo",
					"extraContainers[0].image": "bar",
				},
			},
			wantError: false,
			testFunc: func(t *testing.T, resource *corev1.Deployment) {
				t.Helper()
				require.Equal(t, "foo", resource.Spec.Template.Spec.Containers[0].Name)
				require.Equal(t, "bar", resource.Spec.Template.Spec.Containers[0].Image)
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
			var resource corev1.Deployment
			helm.UnmarshalK8SYaml(t, got, &resource)
			tc.testFunc(t, &resource)
		})
	}
}
