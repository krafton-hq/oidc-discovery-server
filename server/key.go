package server

import (
	"context"
	"github.com/zitadel/oidc/v2/pkg/op"
)

type KeyProvider struct {
}

func NewKeyProvider() op.KeyProvider {
	return &KeyProvider{}
}

func (provider *KeyProvider) KeySet(ctx context.Context) ([]op.Key, error) {
	return nil, nil
}
