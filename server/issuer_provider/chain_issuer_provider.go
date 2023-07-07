package issuer_provider

type ChainIssuerProvider struct {
	providers []IssuerProvider
}

func NewChainIssuerProvider(providers ...IssuerProvider) *ChainIssuerProvider {
	return &ChainIssuerProvider{
		providers: providers,
	}
}

func (provider *ChainIssuerProvider) GetIssuer() []string {
	issuers := make([]string, 0)

	for _, p := range provider.providers {
		issuers = append(issuers, p.GetIssuer()...)
	}

	return issuers
}
