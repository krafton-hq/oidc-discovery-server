package issuer_provider

type ChainIssuerProvider struct {
	providers []IssuerProvider
}

func NewChainIssuerProvider(providers ...IssuerProvider) *ChainIssuerProvider {
	return &ChainIssuerProvider{
		providers: providers,
	}
}

func (provider *ChainIssuerProvider) Issuers() []string {
	issuers := make([]string, 0)

	for _, p := range provider.providers {
		issuers = append(issuers, p.Issuers()...)
	}

	return issuers
}
