package cmd

import (
	"fmt"
	"github.com/fsnotify/fsnotify"
	"github.com/gorilla/mux"
	"github.com/krafton-hq/oidc-discovery-server/issuer_provider"
	"github.com/krafton-hq/oidc-discovery-server/key_provider"
	"github.com/krafton-hq/oidc-discovery-server/server"
	"github.com/spf13/viper"
	"github.com/zitadel/oidc/v2/pkg/op"
	"go.uber.org/zap"
	"net/http"
	"net/url"
	"os"

	"github.com/spf13/cobra"
)

var Issuer string
var Port int

var rootCmd = &cobra.Command{
	Use: "oidc-discovery-server",
	Run: func(cmd *cobra.Command, args []string) {
		zap.S().Info("initializing server...")

		issuerParsed, err := url.Parse(Issuer)
		if err != nil {
			zap.S().Fatalf("issuer is not a valid URL. %v", err)
		}

		issuerProviders := make([]issuer_provider.IssuerProvider, 0)
		if sub := viper.Sub("issuerProvider.http"); sub != nil {
			zap.S().Debugln("adding http issuer provider")
			zap.S().Debugln(sub)
			issuerProviders = append(issuerProviders, issuer_provider.NewHTTPIssuerProvider(sub))
		}
		if sub := viper.Sub("issuerProvider.static"); sub != nil {
			zap.S().Debugln("adding static issuer provider")
			zap.S().Debugln(sub)
			issuerProviders = append(issuerProviders, issuer_provider.NewFileIssuerProvider(sub))
		}

		issuerProvider := issuer_provider.NewChainIssuerProvider(issuerProviders...)

		keyProviders := make([]op.KeyProvider, 0)

		httpKeyProvider := key_provider.NewHTTPKeyProvider(issuerProvider, viper.Sub("keyProvider.http"))
		keyProviders = append(keyProviders, httpKeyProvider)
		if sub := viper.Sub("keyProvider.k8s"); sub != nil {
			zap.S().Debugln("adding k8s key provider")
			zap.S().Debugln(sub)

			provider, err := key_provider.NewK8SKeyProvider()
			if err != nil {
				zap.S().Fatalf("failed to create k8s key provider. %v", err)
			} else {
				keyProviders = append(keyProviders, provider)
			}
		}

		keyProvider := key_provider.NewChainKeyProvider(keyProviders...)

		router := mux.NewRouter()
		err = server.RegisterHandler(router, Issuer, keyProvider, httpKeyProvider)
		if err != nil {
			zap.S().Fatalf("failed to register handler. %v", err)
		}

		http.Handle(issuerParsed.Path, router)

		zap.S().Infof("starting server on port %d\n", Port)
		err = http.ListenAndServe(fmt.Sprintf(":%d", Port), nil)
		if err != nil {
			zap.S().Fatalf("failed to start server. %v", err)
		}
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	zap.ReplaceGlobals(zap.Must(zap.NewProduction()))

	rootCmd.Flags().StringVar(&Issuer, "issuer", "https://localhost:8080/", "Issuer URL (NOTE: / suffix required if no PATH)")
	rootCmd.Flags().IntVarP(&Port, "port", "p", 8080, "Port")
	rootCmd.Flags().StringSlice("issuers", []string{}, "Trusted issuers")
	if err := viper.BindPFlag("issuers", rootCmd.Flags().Lookup("issuers")); err != nil {
		panic(err)
	}

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("config")
	viper.WatchConfig()

	if err := viper.ReadInConfig(); err != nil {
		zap.S().Warnf("failed to read config file. %v", err)
	}

	viper.OnConfigChange(func(e fsnotify.Event) {
		zap.S().Infof("config file changed: %s", e.Name)
	})
}
