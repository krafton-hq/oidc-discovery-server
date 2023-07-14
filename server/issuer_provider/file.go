package issuer_provider

import "github.com/spf13/viper"

type FileIssuerProvider struct {
	config *viper.Viper
}

func NewFileIssuerProvider(config *viper.Viper) *FileIssuerProvider {
	return &FileIssuerProvider{
		config: config,
	}
}

func (provider *FileIssuerProvider) Issuers() []string {
	return provider.config.GetStringSlice("issuers")
}
