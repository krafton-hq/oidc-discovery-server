package cmd

import (
	"fmt"
	"github.krafton.com/sbx/oidc-discovery-server/server"
	"log"
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
		issuerParsed, err := url.Parse(Issuer)
		if err != nil {
			log.Fatalf("issuer is not a valid URL. %v", err)
		}

		keyProvider := server.NewKeyProvider(func() []string {
			return []string{
				Issuer,
				// SAMPLE CODE
				"https://oidc.eks.ap-northeast-2.amazonaws.com/id/F43581740E73025C81BA300EBBEF2E4F",
			}
		})

		http.Handle(issuerParsed.Path, server.Handler(Issuer, keyProvider))

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
}
