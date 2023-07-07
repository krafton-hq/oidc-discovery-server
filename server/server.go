package server

import (
	"github.com/gorilla/mux"
	"github.com/zitadel/oidc/v2/pkg/oidc"
	"github.com/zitadel/oidc/v2/pkg/op"
	"github.krafton.com/sbx/oidc-discovery-server/jwt"
	"net/http"
	"path"
)

const KeysPath = "/keys"

func Handler(issuer string, keyProvider op.KeyProvider) *mux.Router {
	router := mux.NewRouter()

	discoveryConf := oidc.DiscoveryConfiguration{
		Issuer:                           issuer,
		JwksURI:                          path.Join(issuer, KeysPath),
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}

	router.HandleFunc(jwt.OIDCDocumentPath, func(w http.ResponseWriter, r *http.Request) {
		op.Discover(w, &discoveryConf)
	})

	router.HandleFunc(KeysPath, func(w http.ResponseWriter, r *http.Request) {
		op.Keys(w, r, keyProvider)
	})

	return router
}
