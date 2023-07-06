package server

import (
	"context"
	"encoding/json"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/zitadel/oidc/v2/pkg/client"
	"github.com/zitadel/oidc/v2/pkg/op"
	"go.uber.org/zap"
	"gopkg.in/square/go-jose.v2"
	"io"
	"net/http"
	"sync"
	"time"
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

// TODO: move to another code
type CachedJsonWebKeySet struct {
	jose.JSONWebKeySet

	issuer  string
	expires time.Time

	lock sync.Mutex
}

func NewCachedJsonWebKeySet(issuer string) *CachedJsonWebKeySet {
	return &CachedJsonWebKeySet{
		JSONWebKeySet: jose.JSONWebKeySet{},
		issuer:        issuer,
		expires:       time.Now(),
		lock:          sync.Mutex{},
	}
}

func (keySet *CachedJsonWebKeySet) update(ctx context.Context, httpClient *http.Client, force bool) error {
	keySet.lock.Lock()
	defer keySet.lock.Unlock()

	if !keySet.expired(time.Now()) {
		// somehow it's already updated. probably another goroutine.
		log.Debugf("key set is not expired. skipping update.\n")
		return nil
	}

	conf, err := client.Discover(keySet.issuer, httpClient)
	if err != nil {
		return err
	}

	jsonWebKeySet, err := getKeySet(conf.JwksURI, httpClient)
	if err != nil {
		return err
	}

	log.Debugf("updated keys: %v\n", jsonWebKeySet.Keys)

	keySet.JSONWebKeySet = *jsonWebKeySet

	return nil
}

// keySet expires function
func (keySet *CachedJsonWebKeySet) expired(time time.Time) bool {
	return time.After(keySet.expires)
}

// TODO: module-level structured logging
var log *zap.SugaredLogger

func init() {
	log2, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}

	log = log2.Sugar()
}

type KeyProvider struct {
	client *http.Client

	trustedIssuers func() []string
	cachedKeySets  cmap.ConcurrentMap[string, *CachedJsonWebKeySet]
}

func NewKeyProvider(trustedIssuers func() []string) op.KeyProvider {
	return &KeyProvider{
		client:         http.DefaultClient,
		trustedIssuers: trustedIssuers,
		cachedKeySets:  cmap.New[*CachedJsonWebKeySet](),
	}
}

func (provider *KeyProvider) KeySet(ctx context.Context) ([]op.Key, error) {
	keys := make([]op.Key, 0)

	reachedIssuers := make(map[string]bool)

	// TODO: concurrent for-loop
	for _, issuer := range provider.trustedIssuers() {
		log.Infof("lookup issuer: %s\n", issuer)

		if _, ok := reachedIssuers[issuer]; ok {
			log.Warnf("Issuer %s already reached. Skipping.\n", issuer)
		}

		keySet, err := provider.getKeySetFromIssuer(ctx, issuer, false)
		if err != nil {
			log.Warnf("Error getting KeySet from issuer %s: %v\n", issuer, err)
		} else {
			for _, key := range keySet.Keys {
				log.Debugf("appending key: %v\n", key)
				keys = append(keys, &JsonWebKey{key})
			}
		}
	}

	// TODO: add GC code

	return keys, nil
}

func (provider *KeyProvider) getTrustedJWKS(ctx context.Context, issuer string) ([]op.Key, error) {
	return nil, nil
}

func (provider *KeyProvider) getKeySetFromIssuer(ctx context.Context, issuer string, force bool) (*CachedJsonWebKeySet, error) {
	// NOTE: 쓸데없이 객체 생성하긴 하는데 성능 필요한 코드 아니라서 괜찮을 듯
	keySet := NewCachedJsonWebKeySet(issuer)
	if !provider.cachedKeySets.SetIfAbsent(issuer, keySet) {
		var exists bool
		keySet, exists = provider.cachedKeySets.Get(issuer)
		if !exists {
			panic("key set not exists")
		}
	} else {
		log.Debugf("key set not exists. created new one: %v\n", keySet)
	}

	if keySet.expired(time.Now()) {
		log.Infof("keyset expired. issuer: %v\n", keySet.issuer)

		err := keySet.update(ctx, provider.client, force)
		if err != nil {
			return nil, err
		}
	}

	return keySet, nil
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
