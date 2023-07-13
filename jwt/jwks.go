package jwt

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/pquerna/cachecontrol/cacheobject"
	"github.com/zitadel/oidc/v2/pkg/client"
	"github.com/zitadel/oidc/v2/pkg/op"
	"github.krafton.com/sbx/oidc-discovery-server/util/perf"
	"go.uber.org/zap"
	"gopkg.in/square/go-jose.v2"
)

// TODO: module-level structured logging
var log = zap.Must(zap.NewDevelopment()).Sugar()

type CachedJsonWebKeySet struct {
	lock sync.Mutex

	issuer      string
	nextRefresh time.Time
	keys        map[string]JsonWebKey
}

func NewCachedJsonWebKeySet(issuer string) *CachedJsonWebKeySet {
	return &CachedJsonWebKeySet{
		lock:        sync.Mutex{},
		keys:        make(map[string]JsonWebKey),
		issuer:      issuer,
		nextRefresh: time.UnixMilli(0),
	}
}

func (keySet *CachedJsonWebKeySet) Issuer() string {
	return keySet.issuer
}

func (keySet *CachedJsonWebKeySet) Keys() []op.Key {
	if keySet.ShouldRefresh(time.Now()) {
		return nil
	} else {
		keys := make([]op.Key, 0)
		for _, key := range keySet.keys {
			copied := key
			keys = append(keys, &copied)
		}

		return keys
	}
}

func (keySet *CachedJsonWebKeySet) Update(ctx context.Context, httpClient *http.Client, maxTTLSeconds int, force bool) error {
	defer perf.Perf("Update")()

	keySet.lock.Lock()
	defer keySet.lock.Unlock()

	if !force {
		if !keySet.ShouldRefresh(time.Now()) {
			// somehow it's already updated. probably another goroutine.
			log.Debugf("key set is not expired. skipping Update.\n")
			return nil
		}
	} else {
		log.Debugf("force updating KeySet. issuer: %s.\n", keySet.issuer)
	}

	oidcDocumentURL, err := url.JoinPath(keySet.issuer, OIDCDocumentPath)
	if err != nil {
		return errors.Wrap(err, "failed to join url")
	}
	log.Debugf("fetching OIDC document from %s\n", oidcDocumentURL)

	conf, err := client.Discover(keySet.issuer, httpClient)
	if err != nil {
		return errors.Wrapf(err, "failed to discover OIDC configuration. issuer: %s", keySet.issuer)
	}

	fetchedKeySet, ttlSeconds, err := fetchKeySet(conf.JwksURI, httpClient)
	if err != nil {
		return errors.Wrapf(err, "failed to get key set. issuer: %s", keySet.issuer)
	}

	keySet.updateInternalKeySet(fetchedKeySet, time.Now())
	keySet.nextRefresh = time.Now().Add(time.Duration(math.Min(float64(ttlSeconds), float64(maxTTLSeconds))) * time.Second)
	log.Debugf("jwks updated. issuer: %s. next refresh: %s, keys: %s\n", keySet.Issuer(), keySet.nextRefresh, keySet.Keys())

	return nil
}

func (keySet *CachedJsonWebKeySet) updateInternalKeySet(keys []JsonWebKey, now time.Time) {
	oldKeys := make(map[string]JsonWebKey, len(keySet.keys))
	for _, key := range keySet.keys {
		oldKeys[key.KeyID] = key
	}

	for _, key := range oldKeys {
		if key.Expires(now) {
			log.Infof("removing expired key. key id: %s, expires: %s\n", key.KeyID, key.expires)

			delete(keySet.keys, key.KeyID)
		}
	}

	for _, key := range keys {
		if _, ok := keySet.keys[key.KeyID]; ok {
			log.Infof("updating existing key. key id: %s, expires: %s\n", key.KeyID, key.expires)
		} else {
			log.Infof("adding new key. key id: %s, expires: %s\n", key.KeyID, key.expires)
		}

		keySet.keys[key.KeyID] = key
	}
}

// keySet expires function
func (keySet *CachedJsonWebKeySet) ShouldRefresh(time time.Time) bool {
	return time.After(keySet.nextRefresh)
}

func fetchKeySet(jwksUri string, httpClient *http.Client) ([]JsonWebKey, int, error) {
	log.Infof("fetching JWKS from %s\n", jwksUri)

	res, err := httpClient.Get(jwksUri)
	if err != nil {
		return nil, 0, errors.Wrapf(err, "failed to get JWKS from %s", jwksUri)
	}

	cache := res.Header.Get("Cache-Control")
	ttlSeconds := getTTLSeconds(cache)

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, errors.Wrapf(err, "failed to read JWKS response body")
	}

	var data = new(map[string]interface{})

	if err = json.Unmarshal(body, data); err != nil {
		return nil, 0, errors.Wrapf(err, "failed to unmarshal JWKS response body")
	}

	parsedKeys, err := ParseJWKS(body)
	if err != nil {
		return nil, 0, err
	}

	keys := make([]JsonWebKey, 0)
	for _, key := range parsedKeys {
		keys = append(keys, NewJsonWebKey(key, time.Now().Add(time.Duration(ttlSeconds)*time.Second)))
	}

	return keys, ttlSeconds, nil
}

func ParseJWKS(body []byte) ([]jose.JSONWebKey, error) {
	var data = new(map[string]interface{})

	if err := json.Unmarshal(body, data); err != nil {
		return nil, errors.Wrapf(err, "failed to unmarshal JWKS response body")
	}

	keys := make([]jose.JSONWebKey, 0)

	for _, key := range (*data)["keys"].([]interface{}) {
		keyBytes, _ := json.Marshal(key)
		webKey := jose.JSONWebKey{}
		if err := webKey.UnmarshalJSON(keyBytes); err == nil {
			keys = append(keys, webKey)
		} else {
			log.Warnf("failed to unmarshal key: %v\n", err)
		}
	}

	return keys, nil
}

func getTTLSeconds(cacheControlHeader string) int {
	parsed, err := cacheobject.ParseResponseCacheControl(cacheControlHeader)
	if err != nil {
		return 0
	}

	if parsed.NoCachePresent {
		return 0
	}

	return int(math.Max(float64(parsed.MaxAge), 0))
}
