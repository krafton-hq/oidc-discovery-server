package server

import (
	"context"
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/krafton-hq/oidc-discovery-server/jwt"
	"github.com/krafton-hq/oidc-discovery-server/key_provider"
	"github.com/pkg/errors"
	"github.com/zitadel/oidc/v2/pkg/oidc"
	"github.com/zitadel/oidc/v2/pkg/op"
	"net/http"
	"net/url"
)

const KeysPath = "/keys"

func RegisterHandler(router *mux.Router, issuer string, keyProvider op.KeyProvider, httpKeyProvider *key_provider.HTTPKeyProvider) error {
	OIDCHTTPHandler(router, httpKeyProvider)
	err := OIDCHandler(router, issuer, keyProvider)
	if err != nil {
		return err
	}

	return nil
}

// TODO: log error on error handling
func OIDCHandler(router *mux.Router, issuer string, keyProvider op.KeyProvider) error {
	jwksUri, err := url.JoinPath(issuer, KeysPath)
	if err != nil {
		return errors.Wrap(err, "failed to join issuer and keys path. is issuer a valid url?")
	}

	discoveryConf := oidc.DiscoveryConfiguration{
		Issuer:                           issuer,
		JwksURI:                          jwksUri,
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}

	router.HandleFunc(jwt.OIDCDocumentPath, func(w http.ResponseWriter, r *http.Request) {
		op.Discover(w, &discoveryConf)
	})

	router.HandleFunc(KeysPath, func(w http.ResponseWriter, r *http.Request) {
		op.Keys(w, r, keyProvider)
	})

	return nil
}

func OIDCHTTPHandler(router *mux.Router, keyProvider *key_provider.HTTPKeyProvider) {
	keysIssuerPath, _ := url.JoinPath(KeysPath, "{issuer}")
	router.HandleFunc(keysIssuerPath, func(w http.ResponseWriter, r *http.Request) {
		issuer := r.URL.Query().Get("issuer")

		keySet, err := keyProvider.GetKeySetFromIssuer(context.TODO(), issuer, false)
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
}
