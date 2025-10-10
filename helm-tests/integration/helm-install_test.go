package main_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gruntwork-io/terratest/modules/helm"
	"github.com/gruntwork-io/terratest/modules/k8s"
	"github.com/gruntwork-io/terratest/modules/random"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var secretTemplate = `apiVersion: v1
kind: Secret
metadata:
  name: extauthz-signing-keys-secret
type: Opaque
data:
  keyId: %s
  %s.pem: %s`

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

	keyIDFile := "../../examples/keyIDFileConfigmap.yaml"
	k8s.KubectlApply(t, kubeOpts, keyIDFile)
	defer k8s.KubectlDelete(t, kubeOpts, keyIDFile)

	// Generate a private key for the signing key secret
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	privateKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	)

	keyID := "mykeyid1"
	privateKeyPEMBase64Encoded := base64.StdEncoding.EncodeToString(privateKeyPEM)
	keyIDbase64Encoded := base64.StdEncoding.EncodeToString([]byte(keyID))

	secret := fmt.Sprintf(secretTemplate, keyIDbase64Encoded, keyID, privateKeyPEMBase64Encoded)
	k8s.KubectlApplyFromString(t, kubeOpts, secret)
	defer k8s.KubectlDeleteFromString(t, kubeOpts, secret)

	// Create the helm options
	helmOpts := &helm.Options{
		SetValues: map[string]string{
			"namespace":        "default",
			"image.registry":   "localhost",
			"image.repository": app,
			"image.tag":        "latest",
		},
	}
	releaseName := fmt.Sprintf("%s-%s", app, strings.ToLower(random.UniqueId()))

	// Act
	helm.Install(t, helmOpts, path, releaseName)
	defer helm.Delete(t, helmOpts, releaseName, true)

	// Assert
	ctx, cancel1 := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel1()

	// Wait for pod creation
	pods := waitForPodCreation(ctx, t, kubeOpts, "app.kubernetes.io/name="+app)

	// Wait for pod availability
	for _, pod := range pods {
		t.Logf("Checking pod: %s", pod.Name)
		waitForPodAvailability(ctx, t, kubeOpts, pod.Name)
	}

	// Recheck pod availability after a short delay
	t.Log("Rechecking pod availability after a short delay")
	time.Sleep(5 * time.Second)
	for _, pod := range pods {
		t.Logf("Checking pod: %s", pod.Name)
		//nolint:errcheck
		k8s.GetPodLogsE(t, kubeOpts, &pod, app)
		waitForPodAvailability(ctx, t, kubeOpts, pod.Name)
	}
}

func waitForPodCreation(ctx context.Context, t *testing.T, kubeOpts *k8s.KubectlOptions, labelSelector string) []corev1.Pod {
	for {
		select {
		case <-ctx.Done():
			t.Fatal("Timed out waiting for pod creation")
		default:
			pods := k8s.ListPods(t, kubeOpts, metav1.ListOptions{LabelSelector: labelSelector})
			if len(pods) > 0 {
				return pods
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func waitForPodAvailability(ctx context.Context, t *testing.T, kubeOpts *k8s.KubectlOptions, podName string) {
	for {
		select {
		case <-ctx.Done():
			t.Fatal("Timed out waiting for pod availability")
		default:
			pod := k8s.GetPod(t, kubeOpts, podName)
			if k8s.IsPodAvailable(pod) {
				t.Logf("Pod %s is available", podName)
				return
			}
			t.Logf("Pod %s is not available", podName)
			time.Sleep(250 * time.Millisecond)
		}
	}
}
