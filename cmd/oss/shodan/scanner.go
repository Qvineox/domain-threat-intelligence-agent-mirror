package shodan

import (
	"domain-threat-intelligence-agent/cmd/core/entities"
	"domain-threat-intelligence-agent/cmd/core/entities/jobEntities"
	"domain-threat-intelligence-agent/cmd/oss"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
)

const baseURL = "https://api.shodan.io/shodan"
const minuteLimit = 5
const dailyLimit = 5000
const monthlyLimit = 5000

type ScannerImpl struct {
	oss.OpenSourceScanner
}

func NewScannerImpl(apiKey, proxy string) *ScannerImpl {
	client := &http.Client{}

	if len(apiKey) == 0 {
		slog.Warn("api key missing for Shodan scanner.")
	}

	if len(proxy) > 0 {
		proxyUrl, err := url.Parse(proxy)
		if err == nil {
			client.Transport = &http.Transport{Proxy: http.ProxyURL(proxyUrl)}
		}
	}

	return &ScannerImpl{
		oss.OpenSourceScanner{
			Config: entities.ScannerConfig{
				BaseURL:           baseURL,
				APIKey:            apiKey,
				MonthlyQueryLimit: monthlyLimit,
				DailyQueryLimit:   dailyLimit,
				MinuteQueryLimit:  minuteLimit,
			},
			Client: client,
		},
	}
}

func (s *ScannerImpl) GetProvider() jobEntities.SupportedOSSProvider {
	return jobEntities.OSS_PROVIDER_SHODAN
}

func (s *ScannerImpl) ScanTarget(target jobEntities.Target, timeout, retries uint64) ([]byte, error) {
	var content []byte
	var err error

	switch target.Type {
	case jobEntities.HOST_TYPE_CIDR:
		content, err = s.scanIP(target.Host)
	default:
		return nil, errors.New("unsupported host type by Shodan")
	}

	return content, err
}
