package main_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gruntwork-io/terratest/modules/helm"
	"github.com/gruntwork-io/terratest/modules/k8s"
	"github.com/gruntwork-io/terratest/modules/random"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestHelmInstall(t *testing.T) {
	// Create required k8s resources
	kubeOpts := k8s.NewKubectlOptions("", "", "default")

	trustedSubjects := "../../examples/trustedSubjectsConfigmap.yaml"
	k8s.KubectlApply(t, kubeOpts, trustedSubjects)
	defer k8s.KubectlDelete(t, kubeOpts, trustedSubjects)

	systemPolicies := "../../examples/policiesConfigmap1.yaml"
	k8s.KubectlApply(t, kubeOpts, systemPolicies)
	defer k8s.KubectlDelete(t, kubeOpts, systemPolicies)

	userPolicies := "../../examples/policiesConfigmap2.yaml"
	k8s.KubectlApply(t, kubeOpts, userPolicies)
	defer k8s.KubectlDelete(t, kubeOpts, userPolicies)

	// Create the helm options
	helmOpts := &helm.Options{
		SetValues: map[string]string{
			"namespace":      "default",
			"image.registry": "localhost",
			"image.tag":      "latest",
		},
	}
	releaseName := fmt.Sprintf("%s-%s", app, strings.ToLower(random.UniqueId()))

	// Act
	helm.Install(t, helmOpts, path, releaseName)
	defer helm.Delete(t, helmOpts, releaseName, true)

	// Assert
	pods := k8s.ListPods(t, kubeOpts, v1.ListOptions{LabelSelector: "app.kubernetes.io/name=extauthz"})
	t.Logf("Found %d Pod(s)", len(pods))
outerLoop:
	for _, pod := range pods {
		t.Logf("Pod Name: %s", pod.Name)
		for i := range 30 {
			t.Logf("Attempt %d: Checking pod %s to be available...", i+1, pod.Name)
			p := k8s.GetPod(t, kubeOpts, pod.Name)
			//nolint:errcheck
			k8s.GetPodLogsE(t, kubeOpts, p, app)
			if k8s.IsPodAvailable(p) {
				t.Logf("Pod %s is available", pod.Name)
				continue outerLoop
			}
			time.Sleep(2 * time.Second)
		}
		t.Errorf("Pod %s is not available", pod.Name)
	}
}
