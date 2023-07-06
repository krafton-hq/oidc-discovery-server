package server

import (
	"context"
	"encoding/json"
	"github.com/zitadel/oidc/v2/pkg/client"
	"github.com/zitadel/oidc/v2/pkg/op"
	"google.golang.org/appengine/log"
	"gopkg.in/square/go-jose.v2"
	"io"
	"net/http"
)

type JsonWebKey struct {
	jose.JSONWebKey
}

func (key *JsonWebKey) Algorithm() jose.SignatureAlgorithm {
	return jose.SignatureAlgorithm(key.JSONWebKey.Algorithm)
}

func (key *JsonWebKey) Use() string {
	return key.JSONWebKey.Use
}

func (key *JsonWebKey) Key() interface{} {
	return key.JSONWebKey.Key
}

func (key *JsonWebKey) ID() string {
	return key.JSONWebKey.KeyID
}

type CachedJsonWebKeySet struct {
	jose.JSONWebKeySet

	issuer  string
	expires int64
}

type KeyProvider struct {
	client http.Client

	trustedIssuers func() []string
	cachedKeys     []op.Key
}

func NewKeyProvider(trustedIssuers func() []string) op.KeyProvider {
	return &KeyProvider{
		trustedIssuers: trustedIssuers,
	}
}

func (provider *KeyProvider) KeySet(ctx context.Context) ([]op.Key, error) {
	// check and update if invalidate

	return nil, nil
}

func (provider *KeyProvider) getTrustedJWKS(ctx context.Context, issuer string) ([]op.Key, error) {
	return nil, nil
}

func (provider *KeyProvider) getAllKeySets() ([]op.Key, error) {
	keys := make([]op.Key, 0)

	reachedIssuers := make(map[string]bool)

	for _, issuer := range provider.trustedIssuers() {
		if _, ok := reachedIssuers[issuer]; ok {
			log.Warningf(nil, "Issuer %s already reached. Skipping.\n", issuer)
		}

		keySet, err := getKeySetFromIssuer(issuer, &provider.client)
		if err != nil {
			log.Warningf(nil, "Error getting key set from issuer %s: %v\n", issuer, err)
		} else {
			for _, key := range keySet.Keys {
				keys = append(keys, &JsonWebKey{key})
			}
		}
	}

	return keys, nil
}

func getKeySetFromIssuer(issuer string, httpClient *http.Client) (*CachedJsonWebKeySet, error) {
	conf, err := client.Discover(issuer, httpClient)
	if err != nil {
		return nil, err
	}

	keySet, err := getKeySet(conf.JwksURI, httpClient)
	if err != nil {
		return nil, err
	}

	return &CachedJsonWebKeySet{
		JSONWebKeySet: *keySet,
		issuer:        issuer,
		expires:       99999, // TODO: impl this
	}, nil
}

func getKeySet(jwksUri string, httpClient *http.Client) (*jose.JSONWebKeySet, error) {
	res, err := httpClient.Get(jwksUri)
	if err != nil {
		return nil, err
	}

	var keySet *jose.JSONWebKeySet

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(body, keySet)
	if err != nil {
		return nil, err
	}

	return keySet, nil
}
