package main

import (
	"context"
	"github.com/zitadel/oidc/v2/pkg/oidc"
	"github.com/zitadel/oidc/v2/pkg/op"
	"net/http"
	"path"
)

type KeyProvider struct {
}

func (provider *KeyProvider) KeySet(ctx context.Context) ([]op.Key, error) {
	return nil, nil
}

func main() {
	issuer := "https://localhost:8080/"

	discoveryConf := oidc.DiscoveryConfiguration{
		Issuer:                           issuer,
		JwksURI:                          path.Join(issuer, "keys"),
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}

	keyProvider := KeyProvider{}

	http.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		op.Discover(w, &discoveryConf)
	})

	http.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		op.Keys(w, r, &keyProvider)
	})

	http.ListenAndServe(":8080", nil)
}
