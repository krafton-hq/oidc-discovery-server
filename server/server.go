package server

import (
	"context"
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/zitadel/oidc/v2/pkg/oidc"
	"github.com/zitadel/oidc/v2/pkg/op"
	"github.krafton.com/sbx/oidc-discovery-server/jwt"
	"net/http"
	"net/url"
	"path"
)

const KeysPath = "/keys"

// TODO: log error on error handling
func Handler(issuer string, keyProvider KeyProvider) *mux.Router {
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
		op.Keys(w, r, op.KeyProvider(&keyProvider))
	})

	keysIssuerPath, _ := url.JoinPath(KeysPath, "{issuer}")
	router.HandleFunc(keysIssuerPath, func(w http.ResponseWriter, r *http.Request) {
		issuer := r.URL.Query().Get("issuer")

		keySet, err := keyProvider.getKeySetFromIssuer(context.TODO(), issuer, false)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		body, err := json.Marshal(keySet.Keys())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(body); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	return router
}
