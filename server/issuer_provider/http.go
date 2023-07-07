package issuer_provider

import (
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"github.com/tidwall/gjson"
	"github.krafton.com/sbx/oidc-discovery-server/util"
	"go.uber.org/zap"
	"io"
	"net/http"
)

// TODO: module-level structured logging
var log = zap.Must(zap.NewDevelopment()).Sugar()

type HTTPIssuerProvider struct {
	config *viper.Viper
}

func NewHTTPIssuerProvider(config *viper.Viper) *HTTPIssuerProvider {
	return &HTTPIssuerProvider{
		config: config,
	}
}

func (provider *HTTPIssuerProvider) Issuers() []string {
	issuers, err := provider.queryIssuers()
	if err != nil {
		log.Errorf("error while querying issuers: %v", err)
		return []string{}
	}

	return issuers
}

func (provider *HTTPIssuerProvider) queryIssuers() ([]string, error) {
	defer util.Perf("queryIssuers")()
	body, err := provider.queryEndpoint()
	if err != nil {
		return nil, errors.Wrap(err, "error while querying getting issuers")
	}

	gjsonQuery := provider.GJsonQuery()
	log.Debugf("body: %s, gjsonQuery: %s\n", body, gjsonQuery)
	res := gjson.Get(body, gjsonQuery).Array()

	issuers := make([]string, 0)
	for _, value := range res {
		issuers = append(issuers, value.String())
	}

	return issuers, nil
}

func (provider *HTTPIssuerProvider) queryEndpoint() (string, error) {
	endpoint := provider.Endpoint()

	res, err := http.Get(endpoint)
	if err != nil {
		return "", errors.Wrapf(err, "error while fetching issuers from endpoint: %s", endpoint)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", errors.Wrap(err, "error while reading response body")
	}

	return string(body), nil
}

// TODO: support multiple endpoints?
func (provider *HTTPIssuerProvider) Endpoint() string {
	return provider.config.GetString("endpoint")
}

func (provider *HTTPIssuerProvider) GJsonQuery() string {
	return provider.config.GetString("gjsonQuery")
}
