package key_provider

import (
	"context"
	"github.com/krafton-hq/oidc-discovery-server/jwt"
	"github.com/pkg/errors"
	"github.com/zitadel/oidc/v2/pkg/op"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// TODO: out-cluster support?
type K8SKeyProvider struct {
	client *kubernetes.Clientset
}

func NewK8SKeyProvider() (*K8SKeyProvider, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, errors.Wrap(err, "error while getting in-cluster config")
	}

	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &K8SKeyProvider{client: clientSet}, nil
}

func (provider *K8SKeyProvider) KeySet(ctx context.Context) ([]op.Key, error) {
	body, err := provider.client.RESTClient().Get().AbsPath("/openid/v1/jwks").DoRaw(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "error while getting jwks from k8s in-cluster")
	}

	keys, err := jwt.ParseJWKS(body)
	if err != nil {
		return nil, err
	}

	keys2 := make([]op.Key, len(keys))
	for i, key := range keys {
		keys2[i] = &jwt.JsonWebKey{JSONWebKey: key}
	}

	return keys2, nil
}
