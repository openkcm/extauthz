//go:build helmtests

package main_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

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

// logClusterStatus logs the current k8s cluster state for debugging.
// Call this whenever an error occurs to capture cluster state.
func logClusterStatus(t *testing.T, namespace string) {
	t.Helper()
	ctx := t.Context()
	t.Log("=== CLUSTER STATUS (debugging info) ===")

	// Use a short timeout context for kubectl commands
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// All pods across all namespaces
	t.Log("--- All Pods (all namespaces) ---")
	out, _ := exec.CommandContext(ctx, "kubectl", "get", "pods", "-A", "-o", "wide").CombinedOutput()
	t.Log(string(out))

	// Services in the target namespace
	t.Logf("--- Services (namespace: %s) ---", namespace)
	out, _ = exec.CommandContext(ctx, "kubectl", "get", "services", "-n", namespace).CombinedOutput()
	t.Log(string(out))

	// Recent events sorted by timestamp
	t.Logf("--- Events (namespace: %s, sorted by lastTimestamp) ---", namespace)
	out, _ = exec.CommandContext(ctx, "kubectl", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp").CombinedOutput()
	t.Log(string(out))

	// Pod descriptions for detailed container status
	t.Logf("--- Pod Descriptions (namespace: %s) ---", namespace)
	out, _ = exec.CommandContext(ctx, "kubectl", "describe", "pods", "-n", namespace).CombinedOutput()
	t.Log(string(out))

	t.Log("=== END CLUSTER STATUS ===")
}

// getK8sClient creates a kubernetes clientset using default kubeconfig.
func getK8sClient(t *testing.T) *kubernetes.Clientset {
	t.Helper()

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)

	config, err := kubeConfig.ClientConfig()
	if err != nil {
		t.Fatalf("failed to get kubeconfig: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatalf("failed to create kubernetes client: %v", err)
	}

	return clientset
}

// helmInstall installs a helm chart and returns error.
func helmInstall(ctx context.Context, t *testing.T, namespace, releaseName, chart string, values map[string]string, extraArgs ...string) error {
	t.Helper()
	// Preallocate args slice: 5 base args + 2 per value + extraArgs
	args := make([]string, 0, 5+2*len(values)+len(extraArgs))
	args = append(args, "install", releaseName, chart, "-n", namespace)
	for k, v := range values {
		args = append(args, "--set", fmt.Sprintf("%s=%s", k, v))
	}
	args = append(args, extraArgs...)

	cmd := exec.CommandContext(ctx, "helm", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	t.Logf("Running: helm %s", strings.Join(args, " "))
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("helm install failed: %w\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
	t.Logf("Installed helm release %s", releaseName)
	return nil
}

// helmDelete removes a helm release.
func helmDelete(ctx context.Context, t *testing.T, namespace, releaseName string) {
	t.Helper()
	args := []string{"uninstall", releaseName, "-n", namespace}

	cmd := exec.CommandContext(ctx, "helm", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Warning: helm uninstall %s failed: %v\nOutput: %s", releaseName, err, string(out))
		return
	}
	t.Logf("Deleted helm release %s", releaseName)
}

// kubectlApply applies a yaml file.
func kubectlApply(ctx context.Context, t *testing.T, filePath string) error {
	t.Helper()
	cmd := exec.CommandContext(ctx, "kubectl", "apply", "-f", filePath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("kubectl apply failed: %w\nOutput: %s", err, string(out))
	}
	t.Logf("Applied %s", filePath)
	return nil
}

// kubectlDelete deletes resources from a yaml file.
func kubectlDelete(ctx context.Context, t *testing.T, filePath string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, "kubectl", "delete", "-f", filePath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Warning: kubectl delete %s failed: %v\nOutput: %s", filePath, err, string(out))
	}
}

// kubectlApplyFromString applies yaml content from a string.
func kubectlApplyFromString(ctx context.Context, t *testing.T, content string) error {
	t.Helper()
	cmd := exec.CommandContext(ctx, "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(content)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("kubectl apply from string failed: %w\nOutput: %s", err, string(out))
	}
	t.Log("Applied yaml from string")
	return nil
}

// kubectlDeleteFromString deletes resources from yaml content.
func kubectlDeleteFromString(ctx context.Context, t *testing.T, content string) {
	t.Helper()
	cmd := exec.CommandContext(ctx, "kubectl", "delete", "-f", "-")
	cmd.Stdin = strings.NewReader(content)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Warning: kubectl delete from string failed: %v\nOutput: %s", err, string(out))
	}
}

// isPodReady checks if a pod is in ready state.
func isPodReady(pod *corev1.Pod) bool {
	if pod.Status.Phase != corev1.PodRunning {
		return false
	}
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// generateUniqueID generates a unique 8-character hex ID.
func generateUniqueID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// TestHelmInstall tests helm installation using os/exec and k8s client-go.
// On any error, it logs the current k8s cluster status for debugging.
func TestHelmInstall(t *testing.T) {
	ctx := t.Context()
	namespace := "default"

	// Initialize k8s client
	client := getK8sClient(t)

	// Create required resources
	trustedSubjects := "../../examples/trustedSubjectsConfigmap.yaml"
	err := kubectlApply(ctx, t, trustedSubjects)
	if err != nil {
		logClusterStatus(t, namespace)
		t.Fatalf("failed to apply trusted subjects: %v", err)
	}
	defer kubectlDelete(ctx, t, trustedSubjects)

	systemPolicies := "../../examples/policiesConfigmap1.yaml"
	err = kubectlApply(ctx, t, systemPolicies)
	if err != nil {
		logClusterStatus(t, namespace)
		t.Fatalf("failed to apply system policies: %v", err)
	}
	defer kubectlDelete(ctx, t, systemPolicies)

	userPolicies := "../../examples/policiesConfigmap2.yaml"
	err = kubectlApply(ctx, t, userPolicies)
	if err != nil {
		logClusterStatus(t, namespace)
		t.Fatalf("failed to apply user policies: %v", err)
	}
	defer kubectlDelete(ctx, t, userPolicies)

	keyIDFile := "../../examples/keyIDFileConfigmap.yaml"
	err = kubectlApply(ctx, t, keyIDFile)
	if err != nil {
		logClusterStatus(t, namespace)
		t.Fatalf("failed to apply keyID file: %v", err)
	}
	defer kubectlDelete(ctx, t, keyIDFile)

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
	err = kubectlApplyFromString(ctx, t, secret)
	if err != nil {
		logClusterStatus(t, namespace)
		t.Fatalf("failed to apply signing key secret: %v", err)
	}
	defer kubectlDeleteFromString(ctx, t, secret)

	// Install extauthz
	releaseName := fmt.Sprintf("%s-%s", app, strings.ToLower(generateUniqueID()))
	extauthzValues := map[string]string{
		"namespace":        "default",
		"image.registry":   "localhost",
		"image.repository": app,
		"image.tag":        "latest",
		"image.pullPolicy": "Never",
	}
	err = helmInstall(ctx, t, namespace, releaseName, path, extauthzValues, "--timeout", "5m", "--wait")
	if err != nil {
		logClusterStatus(t, namespace)
		t.Fatalf("failed to install extauthz: %v", err)
	}
	defer helmDelete(ctx, t, namespace, releaseName)

	// Verify deployment
	t.Log("Verifying deployment after helm install completed")

	// Get all extauthz pods
	pods, err := client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/name=" + app,
	})
	if err != nil {
		logClusterStatus(t, namespace)
		t.Fatalf("failed to list pods: %v", err)
	}
	t.Logf("Found %d pod(s) after installation", len(pods.Items))

	// Check each pod's status
	for _, pod := range pods.Items {
		t.Logf("Pod %s: phase=%s", pod.Name, pod.Status.Phase)

		// Log container logs for each pod
		for _, container := range pod.Spec.Containers {
			logOpts := &corev1.PodLogOptions{
				Container: container.Name,
			}
			req := client.CoreV1().Pods(namespace).GetLogs(pod.Name, logOpts)
			logStream, err := req.Stream(ctx)
			if err != nil {
				t.Logf("Failed to get logs for pod %s container %s: %v", pod.Name, container.Name, err)
				continue
			}
			var logBuf bytes.Buffer
			_, _ = io.Copy(&logBuf, logStream)
			logStream.Close()
			t.Logf("Logs for pod %s container %s:\n%s", pod.Name, container.Name, logBuf.String())
		}

		// Regular pods should be Running
		if pod.Status.Phase != corev1.PodRunning || !isPodReady(&pod) {
			logClusterStatus(t, namespace)
			t.Errorf("Expected pod %s to be Running and available, got phase=%s available=%v",
				pod.Name, pod.Status.Phase, isPodReady(&pod))
		}
	}

	// Verify services exist
	t.Log("Verifying services")
	service, err := client.CoreV1().Services(namespace).Get(ctx, releaseName, metav1.GetOptions{})
	if err != nil {
		logClusterStatus(t, namespace)
		t.Fatalf("Expected service to exist: %v", err)
	}
	t.Logf("Service %s exists with type %s", service.Name, service.Spec.Type)
}
