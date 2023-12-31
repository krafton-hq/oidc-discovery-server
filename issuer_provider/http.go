package issuer_provider

import (
	"github.com/krafton-hq/oidc-discovery-server/util/perf"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"
	"io"
	"net/http"
)

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
		zap.S().Errorf("error while querying issuers: %v", err)
		return []string{}
	}

	return issuers
}

func (provider *HTTPIssuerProvider) queryIssuers() ([]string, error) {
	defer perf.Perf("queryIssuers")()
	body, err := provider.queryEndpoint()
	if err != nil {
		return nil, errors.Wrap(err, "error while querying getting issuers")
	}

	gjsonQuery := provider.GJsonQuery()
	zap.S().Debugf("body: %s, gjsonQuery: %s\n", body, gjsonQuery)
	res := gjson.Get(body, gjsonQuery).Array()

	issuers := make([]string, 0)
	for _, value := range res {
		issuers = append(issuers, value.String())
	}

	return issuers, nil
}

func (provider *HTTPIssuerProvider) queryEndpoint() (string, error) {
	defer perf.Perf("queryEndpoint")()
	endpoint := provider.Endpoint()

	defer perf.Perf("queryEndpoint.http.Get")()
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

func (provider *HTTPIssuerProvider) MaxTTLSeconds() int {
	return provider.config.GetInt("maxTTLSeconds")
}
