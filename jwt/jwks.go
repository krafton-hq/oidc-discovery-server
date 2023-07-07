package jwt

import (
	"context"
	"encoding/json"
	"github.com/pkg/errors"
	"github.com/pquerna/cachecontrol/cacheobject"
	"github.com/zitadel/oidc/v2/pkg/client"
	"go.uber.org/zap"
	"gopkg.in/square/go-jose.v2"
	"io"
	"math"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// TODO: module-level structured logging
var log *zap.SugaredLogger

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
		expires:       time.UnixMilli(0),
		lock:          sync.Mutex{},
	}
}

func (keySet *CachedJsonWebKeySet) Issuer() string {
	return keySet.issuer
}

func (keySet *CachedJsonWebKeySet) Update(ctx context.Context, httpClient *http.Client, force bool) error {
	keySet.lock.Lock()
	defer keySet.lock.Unlock()

	if !force {
		if !keySet.Expired(time.Now()) {
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

	jsonWebKeySet, ttl, err := GetKeySet(conf.JwksURI, httpClient)
	if err != nil {
		return errors.Wrapf(err, "failed to get key set. issuer: %s", keySet.issuer)
	}

	log.Debugf("updated keys: %v\n", jsonWebKeySet.Keys)

	keySet.JSONWebKeySet = *jsonWebKeySet
	keySet.expires = time.Now().Add(time.Duration(ttl) * time.Second)

	return nil
}

// keySet expires function
func (keySet *CachedJsonWebKeySet) Expired(time time.Time) bool {
	return time.After(keySet.expires)
}

func GetKeySet(jwksUri string, httpClient *http.Client) (*jose.JSONWebKeySet, int, error) {
	log.Infof("fetching JWKS from %s\n", jwksUri)

	res, err := httpClient.Get(jwksUri)
	if err != nil {
		return nil, 0, errors.Wrapf(err, "failed to get JWKS from %s", jwksUri)
	}

	cache := res.Header.Get("Cache-Control")
	ttl := getTTL(cache)

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, errors.Wrapf(err, "failed to read JWKS response body")
	}

	var data = new(map[string]interface{})

	if err = json.Unmarshal(body, data); err != nil {
		return nil, 0, errors.Wrapf(err, "failed to unmarshal JWKS response body")
	}

	jwks := jose.JSONWebKeySet{Keys: nil}

	for _, key := range (*data)["keys"].([]interface{}) {
		keyBytes, _ := json.Marshal(key)
		webKey := new(jose.JSONWebKey)
		if err := webKey.UnmarshalJSON(keyBytes); err == nil {
			jwks.Keys = append(jwks.Keys, *webKey)
		} else {
			log.Warnf("failed to unmarshal key: %v\n", err)
		}
	}

	return &jwks, ttl, nil
}

func getTTL(cacheControlHeader string) int {
	parsed, err := cacheobject.ParseResponseCacheControl(cacheControlHeader)
	if err != nil {
		return 0
	}

	if parsed.NoCachePresent {
		return 0
	}

	return int(math.Max(float64(parsed.MaxAge), 0))
}
