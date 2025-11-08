package k8s

import (
	"fmt"
	"os"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type RemoteJWKS struct {
	// URI is the HTTPS URI to fetch the JWKS. Envoy's system trust bundle is used to validate the server certificate.
	// If a custom trust bundle is needed, it can be specified in a BackendTLSConfig resource and target the BackendRefs.
	URI string `json:"uri"`
}

type JWTProviderSpec struct {
	// Name defines a unique name for the JWT provider. A name can have a variety of forms,
	// including RFC1123 subdomains, RFC 1123 labels, or RFC 1035 labels.
	Name string `json:"name"`

	// Issuer is the principal that issued the JWT and takes the form of a URL or email address.
	// For additional details, see https://tools.ietf.org/html/rfc7519#section-4.1.1 for
	// URL format and https://rfc-editor.org/rfc/rfc5322.html for email format. If not provided,
	// the JWT issuer is not checked.
	Issuer string `json:"issuer"`

	// Audiences is a list of JWT audiences allowed access. For additional details, see
	// https://tools.ietf.org/html/rfc7519#section-4.1.3. If not provided, JWT audiences
	// are not checked.
	Audiences []string `json:"audiences,omitempty"`

	// JWKS can be fetched from remote server via HTTP/HTTPS. This field specifies the remote HTTP
	// URI and how the fetched JWKS should be cached.
	RemoteJwks *RemoteJWKS `json:"remoteJwks"`
}

type JWTProvider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec JWTProviderSpec `json:"spec"`
}

func DynamicClient() (*dynamic.DynamicClient, error) {
	config, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG_PATH"))
	if err != nil {
		// If no kubeconfig found, try in-cluster config (for pods)
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to load the k8s kubeconfig: %w", err)
		}
	}

	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s dynamic client: %w", err)
	}

	return dynClient, nil
}
