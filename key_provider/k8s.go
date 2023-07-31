package key_provider

import (
	"context"
	"github.com/krafton-hq/oidc-discovery-server/jwt"
	"github.com/pkg/errors"
	"github.com/zitadel/oidc/v2/pkg/op"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"time"
)

// TODO: out-cluster support?
type K8SKeyProvider struct {
	client  *kubernetes.Clientset
	keys    []op.Key
	expires time.Time
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

	return &K8SKeyProvider{
		clientSet,
		nil,
		time.Now(),
	}, nil
}

func (provider *K8SKeyProvider) KeySet(ctx context.Context) ([]op.Key, error) {
	if provider.Expires(time.Now()) {
		err := provider.update(ctx)
		if err != nil {
			return nil, err
		}
	}

	return provider.keys, nil
}

func (provider *K8SKeyProvider) update(ctx context.Context) error {
	body, err := provider.client.RESTClient().Get().AbsPath("/openid/v1/jwks").DoRaw(ctx)
	if err != nil {
		return errors.Wrap(err, "error while getting jwks from k8s in-cluster")
	}

	keys, err := jwt.ParseJWKS(body)
	if err != nil {
		return errors.Wrap(err, "error while parsing jwks from k8s in-cluster")
	}

	keys2 := make([]op.Key, len(keys))
	for i, key := range keys {
		keys2[i] = &jwt.JsonWebKey{JSONWebKey: key}
	}

	provider.keys = keys2
	provider.expires = time.Now().Add(60 * time.Second)

	return nil
}

func (provider *K8SKeyProvider) Expires(now time.Time) bool {
	return provider.expires.Before(now)
}
