package server

import (
	"github.com/gorilla/mux"
	"github.com/zitadel/oidc/v2/pkg/oidc"
	"github.com/zitadel/oidc/v2/pkg/op"
	"net/http"
	"path"
)

const OIDCDocumentEndpoint = "/.well-known/openid-configuration"
const KeysEndpoint = "/keys"

func Handler(issuer string, keyProvider op.KeyProvider) *mux.Router {
	router := mux.NewRouter()

	discoveryConf := oidc.DiscoveryConfiguration{
		Issuer:                           issuer,
		JwksURI:                          path.Join(issuer, KeysEndpoint),
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}

	router.HandleFunc(OIDCDocumentEndpoint, func(w http.ResponseWriter, r *http.Request) {
		op.Discover(w, &discoveryConf)
	})

	router.HandleFunc(KeysEndpoint, func(w http.ResponseWriter, r *http.Request) {
		op.Keys(w, r, keyProvider)
	})

	return router
}
