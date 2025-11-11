package oidc

import (
	"context"
	"log/slog"
	"time"

	"github.com/samber/oops"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"

	slogctx "github.com/veqryn/slog-context"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkcm/extauthz/internal/config"
	"github.com/openkcm/extauthz/internal/k8s"
)

func (h *Handler) startK8SProviderWatcher(stopCh chan struct{}, cfg *config.K8SProviderRef) error {
	if cfg == nil {
		return nil
	}

	gvr := schema.GroupVersionResource{
		Group:    cfg.Group,
		Version:  cfg.Version,
		Resource: cfg.Resource,
	}

	client, err := k8s.DynamicClient()
	if err != nil {
		return oops.In("k8s " + cfg.Resource + " watcher").
			Hint("could not create dynamic client").
			Wrap(err)
	}

	factory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(
		client,
		30*time.Second,
		cfg.Namespace,
		nil,
	)
	defer func() {
		factory.Start(stopCh)
		factory.WaitForCacheSync(stopCh)
	}()

	informer := factory.ForResource(gvr).Informer()
	_, err = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    h.addJWTProvider,
		UpdateFunc: h.updateJWTProvider,
		DeleteFunc: h.deleteJWTProvider,
	})
	if err != nil {
		return oops.In("K8S " + cfg.Resource + " watcher").
			Hint("Cound not create the K8S watcher for " + cfg.Resource).
			Wrap(err)
	}

	list, err := client.Resource(gvr).Namespace(cfg.Namespace).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return oops.In("K8S " + cfg.Resource + "watcher").
			Hint("Cound not list existing K8S " + cfg.Resource).
			Wrap(err)
	}
	for _, item := range list.Items {
		h.addJWTProvider(&item)
	}

	slog.Info("K8S watcher started successfully", "resource", cfg.Resource)

	<-stopCh // block forever (or until stopped)

	return nil
}

func (h *Handler) addJWTProvider(obj interface{}) {
	unsJWTProv, ok := obj.(*unstructured.Unstructured)
	if ok {
		ctx := context.Background()

		slogctx.Info(ctx, "Processing the Add event for K8S JWTProvider", "name", unsJWTProv.GetName())

		k8sJWTProvider, err := ConvertUnstructuredJWTProvider(unsJWTProv)
		if err != nil {
			slog.Error("Failed to convert unstructured to JWTProvider", "name", unsJWTProv.GetName(), "error", err)
			return
		}

		p := convertJWTProviderToProvider(ctx, k8sJWTProvider)
		if p != nil {
			h.registerProvider(p)
		}
	}
}

func (h *Handler) updateJWTProvider(oldObj, newObj interface{}) {
	oldUnsJWTProv, ook := oldObj.(*unstructured.Unstructured)
	newUnsJWTProv, nok := newObj.(*unstructured.Unstructured)
	if nok && ook {
		ctx := context.Background()

		slogctx.Info(ctx, "Processing the RefreshConfiguration event for K8S JWTProvider", "name", oldUnsJWTProv.GetName())

		old, err := ConvertUnstructuredJWTProvider(oldUnsJWTProv)
		if err != nil {
			slog.Error("Failed to convert unstructured new object to JWTProvider", "name", oldUnsJWTProv.GetName(), "error", err)
			return
		}
		nld, err := ConvertUnstructuredJWTProvider(newUnsJWTProv)
		if err != nil {
			slog.Error("Failed to convert unstructured new object to JWTProvider", "name", newUnsJWTProv.GetName(), "error", err)
			return
		}

		oldp := convertJWTProviderToProvider(ctx, old)
		newp := convertJWTProviderToProvider(ctx, nld)
		if newp != nil {
			h.swapProvider(oldp, newp)
		}
	}
}

func (h *Handler) deleteJWTProvider(obj interface{}) {
	unsJWTProv, ok := obj.(*unstructured.Unstructured)

	if ok {
		ctx := context.Background()

		slogctx.Info(ctx, "Processing the Delete event for K8S JWTProvider", "name", unsJWTProv.GetName())

		k8sJWTProvider, err := ConvertUnstructuredJWTProvider(unsJWTProv)
		if err != nil {
			slog.Error("Failed to convert unstructured to JWTProvider", "name", unsJWTProv.GetName(), "error", err)
			return
		}

		p := convertJWTProviderToProvider(ctx, k8sJWTProvider)
		if p != nil {
			h.unRegisterProvider(p)
		}
	}
}

// ConvertUnstructuredJWTProvider converts an unstructured object to a typed JWTProvider.
func ConvertUnstructuredJWTProvider(obj *unstructured.Unstructured) (*k8s.JWTProvider, error) {
	jwtProv := &k8s.JWTProvider{}

	err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, jwtProv)
	if err != nil {
		return nil, err
	}

	return jwtProv, nil
}

func convertJWTProviderToProvider(ctx context.Context, srcProvider *k8s.JWTProvider) *Provider {
	if srcProvider == nil {
		slogctx.Error(ctx, "Failed to convert the  K8S JWTProvider as is nil")
		return nil
	}

	issuerURL, err := parseEndpoint(srcProvider.Spec.Issuer)
	if err != nil {
		slogctx.Error(ctx, "Failed to convert issuer url field of the K8S JWTProvider",
			"name", srcProvider.Spec.Name, "error", err)
		return nil
	}
	jwksURL, err := parseEndpoint(srcProvider.Spec.RemoteJwks.URI)
	if err != nil {
		slogctx.Error(ctx, "Failed to convert jwks uri field of the K8S JWTProvider",
			"name", srcProvider.Spec.Name, "error", err)
		return nil
	}

	oidcProvider, err := NewProvider(issuerURL, srcProvider.Spec.Audiences, WithJWKSURI(jwksURL))
	if err != nil {
		slogctx.Error(ctx, "Failed to create the provider for the K8S JWTProvider",
			"name", srcProvider.Spec.Name, "error", err)
		return nil
	}
	err = oidcProvider.RefreshConfiguration(ctx)
	if err != nil {
		slogctx.Error(ctx, "Failed to refresh provider configuration",
			"name", srcProvider.Spec.Name, "error", err)
		return nil
	}

	return oidcProvider
}
