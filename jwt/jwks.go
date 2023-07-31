package jwt

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/krafton-hq/oidc-discovery-server/util/perf"
	"github.com/pkg/errors"
	"github.com/pquerna/cachecontrol/cacheobject"
	"github.com/zitadel/oidc/v2/pkg/client"
	"github.com/zitadel/oidc/v2/pkg/op"
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

// Update updates keySet in place
// ctx: context
// httpClient: http client to use
// defaultKeyTTL: default key TTL if no cache-control header defined in response
// maxKeyTTL: max key TTL
// force: force update even if keySet is not expired
func (keySet *CachedJsonWebKeySet) Update(
	ctx context.Context,
	httpClient *http.Client,
	defaultKeyTTL, maxKeyTTL time.Duration,
	force bool,
) error {
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

	fetchedKeySet, keyTTL, err := fetchKeySet(conf.JwksURI, httpClient, defaultKeyTTL)
	if err != nil {
		return errors.Wrapf(err, "failed to get key set. issuer: %s", keySet.issuer)
	}

	if keyTTL > maxKeyTTL {
		keyTTL = maxKeyTTL
	}

	keySet.updateInternalKeySet(fetchedKeySet, time.Now())
	keySet.nextRefresh = time.Now().Add(keyTTL)
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

func fetchKeySet(jwksUri string, httpClient *http.Client, defaultKeyTTL time.Duration) ([]JsonWebKey, time.Duration, error) {
	log.Infof("fetching JWKS from %s\n", jwksUri)

	res, err := httpClient.Get(jwksUri)
	if err != nil {
		return nil, 0, errors.Wrapf(err, "failed to get JWKS from %s", jwksUri)
	}

	cache := res.Header.Get("Cache-Control")
	keyTTL := getKeyTTL(cache)
	if keyTTL < 0 {
		keyTTL = defaultKeyTTL
	}

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
		keys = append(keys, NewJsonWebKey(key, time.Now().Add(keyTTL)))
	}

	return keys, keyTTL, nil
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

func getKeyTTL(cacheControlHeader string) time.Duration {
	parsed, err := cacheobject.ParseResponseCacheControl(cacheControlHeader)
	if err != nil {
		return -1
	}

	if parsed.NoCachePresent {
		return -1
	}

	return time.Duration(parsed.MaxAge) * time.Second
}
