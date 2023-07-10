package cmd

import (
	"fmt"
	"github.com/krafton-hq/oidc-discovery-server/issuer_provider"
	"github.com/krafton-hq/oidc-discovery-server/server"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"net/http"
	"net/url"
	"os"

	"github.com/spf13/cobra"
)

// TODO: module-level structured logging
var log = zap.Must(zap.NewDevelopment()).Sugar()

var Issuer string
var Port int

var rootCmd = &cobra.Command{
	Use: "oidc-discovery-server",
	Run: func(cmd *cobra.Command, args []string) {
		log.Info("initializing server...")

		issuerParsed, err := url.Parse(Issuer)
		if err != nil {
			log.Fatalf("issuer is not a valid URL. %v", err)
		}

		issuerProviders := make([]issuer_provider.IssuerProvider, 0)
		if sub := viper.Sub("issuerProvider.http"); sub != nil {
			log.Debugln("adding http issuer provider")
			log.Debugln(sub)
			issuerProviders = append(issuerProviders, issuer_provider.NewHTTPIssuerProvider(sub))
		}
		if sub := viper.Sub("issuerProvider.static"); sub != nil {
			log.Debugln("adding static issuer provider")
			log.Debugln(sub)
			issuerProviders = append(issuerProviders, issuer_provider.NewFileIssuerProvider(sub))
		}

		issuerProvider := issuer_provider.NewChainIssuerProvider(issuerProviders...)
		keyProvider := server.NewKeyProvider(issuerProvider)

		http.Handle(issuerParsed.Path, server.Handler(Issuer, keyProvider))

		log.Infof("starting server on port %d\n", Port)
		err = http.ListenAndServe(fmt.Sprintf(":%d", Port), nil)
		if err != nil {
			log.Fatalf("failed to start server. %v", err)
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
	rootCmd.Flags().StringVar(&Issuer, "issuer", "https://localhost:8080/", "Issuer URL (NOTE: / suffix required if no PATH)")
	rootCmd.Flags().IntVarP(&Port, "port", "p", 8080, "Port")
	rootCmd.Flags().StringSlice("issuers", []string{}, "Trusted issuers")
	if err := viper.BindPFlag("issuers", rootCmd.Flags().Lookup("issuers")); err != nil {
		panic(err)
	}

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.WatchConfig()

	if err := viper.ReadInConfig(); err != nil {
		log.Warnf("failed to read config file. %v", err)
	}
}
