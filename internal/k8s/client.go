package k8s

import (
	"fmt"
	"os"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

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
