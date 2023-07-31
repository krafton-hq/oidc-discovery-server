package key_provider

import (
	"context"
	"github.com/fanliao/go-promise"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"github.com/zitadel/oidc/v2/pkg/op"
	"github.krafton.com/sbx/oidc-discovery-server/issuer_provider"
	"github.krafton.com/sbx/oidc-discovery-server/jwt"
	"github.krafton.com/sbx/oidc-discovery-server/util/perf"
	"go.uber.org/zap"
	"net/http"
	"time"
)

// TODO: module-level structured logging
var log = zap.Must(zap.NewDevelopment()).Sugar()

type HTTPKeyProvider struct {
	client         *http.Client
	config         *viper.Viper
	issuerProvider issuer_provider.IssuerProvider
	cachedKeySets  cmap.ConcurrentMap[string, *jwt.CachedJsonWebKeySet]
}

func NewHTTPKeyProvider(issuerProvider issuer_provider.IssuerProvider, config *viper.Viper) *HTTPKeyProvider {
	if config == nil {
		config = viper.New()
		// TODO: remove magic strings
		config.Set("maxTTLSeconds", 300)
	}

	return &HTTPKeyProvider{
		client:         http.DefaultClient,
		config:         config,
		issuerProvider: issuerProvider,
		cachedKeySets:  cmap.New[*jwt.CachedJsonWebKeySet](),
	}
}

func (provider *HTTPKeyProvider) KeysInCache(issuer string) (*jwt.CachedJsonWebKeySet, bool) {
	keySet, exists := provider.cachedKeySets.Get(issuer)

	// copy to avoid modifying keySet in outside
	return &*keySet, exists
}

func (provider *HTTPKeyProvider) KeySet(ctx context.Context) ([]op.Key, error) {
	defer perf.Perf("KeySet")()

	reachedIssuers := cmap.New[struct{}]()
	promises := make([]interface{}, 0)

	for _, issuer := range provider.issuerProvider.Issuers() {
		p := promise.NewPromise()
		promises = append(promises, p)
		issuer := issuer

		go func() {
			keys := make([]op.Key, 0)
			log.Infof("lookup issuer: %s\n", issuer)

			if reachedIssuers.SetIfAbsent(issuer, struct{}{}) {
				keySet, err := provider.GetKeySetFromIssuer(ctx, issuer, false)
				if err != nil {
					log.Warnf("Error getting KeySet from issuer %s: %+v\n", issuer, err)
				} else {
					for _, key := range keySet.Keys() {
						log.Debugf("key: %s\n", key.ID())
						keys = append(keys, key)
					}
				}
			} else {
				log.Warnf("Issuer %s already reached. Skipping.\n", issuer)
			}

			log.Infof("resolved %d keys.\n", len(keys))
			if err := p.Resolve(keys); err != nil {
				log.Error(err)
			}
		}()
	}

	res := promise.WhenAll(promises...)
	values, err := res.Get()
	if err != nil {
		return nil, errors.Wrapf(err, "error while fetching multiple keys from issuers")
	}

	result := make([]op.Key, 0)
	checked := make(map[string]struct{})

	for _, value := range values.([]interface{}) {
		keys, err := value.(*promise.Promise).Get()
		if err != nil {
			log.Error(err)
			continue
		}

		for _, key := range keys.([]op.Key) {
			if _, ok := checked[key.ID()]; ok {
				log.Warnf("kid %s already exists. skipping.\n", key.ID())
				continue
			}

			checked[key.ID()] = struct{}{}
			result = append(result, key)
		}
	}

	return result, nil
}

func (provider *HTTPKeyProvider) GetKeySetFromIssuer(ctx context.Context, issuer string, force bool) (*jwt.CachedJsonWebKeySet, error) {
	// NOTE: 쓸데없이 객체 생성하긴 하는데 성능 필요한 코드 아니라서 괜찮을 듯
	keySet := jwt.NewCachedJsonWebKeySet(issuer)
	if !provider.cachedKeySets.SetIfAbsent(issuer, keySet) {
		var exists bool
		keySet, exists = provider.cachedKeySets.Get(issuer)
		if !exists {
			panic("key set not exists")
		}
	} else {
		log.Debugf("key set not exists. created new one: %v\n", keySet)
	}

	if keySet.ShouldRefresh(time.Now()) {
		log.Infof("keyset expired. issuer: %v\n", keySet.Issuer())

		err := keySet.Update(ctx, provider.client, provider.MaxTTLSeconds(), force)
		if err != nil {
			return nil, err
		}
	} else {
		log.Debugln("keyset not expired. skipping update.")
	}

	return keySet, nil
}

func (provider *HTTPKeyProvider) MaxTTLSeconds() int {
	return provider.config.GetInt("maxTTLSeconds")
}

func (provider *HTTPKeyProvider) GetDefaultKeyTTLSeconds() int {
	return provider.config.GetInt("defaultKeyTTLSeconds")
}
