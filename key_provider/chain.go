package key_provider

import (
	"context"
	"github.com/zitadel/oidc/v2/pkg/op"
)

type ChainKeyProvider struct {
	providers []op.KeyProvider
}

func NewChainKeyProvider(providers ...op.KeyProvider) *ChainKeyProvider {
	return &ChainKeyProvider{
		providers: providers,
	}
}

func (c ChainKeyProvider) KeySet(ctx context.Context) ([]op.Key, error) {
	var keys []op.Key

	for _, provider := range c.providers {
		keySet, err := provider.KeySet(ctx)
		if err != nil {
			log.Warnf("error while getting keyset from provider: %s", err)
		} else {
			keys = append(keys, keySet...)
		}
	}

	return keys, nil
}
