package ipQualityScore

import (
	"domain-threat-intelligence-agent/cmd/core/entities"
	"domain-threat-intelligence-agent/cmd/core/entities/jobEntities"
	"domain-threat-intelligence-agent/cmd/oss"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
)

const baseURL = "https://www.ipqualityscore.com/api/json"
const minuteLimit = 10
const dailyLimit = 5000
const monthlyLimit = 5000

type ScannerImpl struct {
	oss.OpenSourceScanner
}

func NewScannerImpl(apiKey, proxy string) *ScannerImpl {
	client := &http.Client{}

	if len(apiKey) == 0 {
		slog.Warn("api key missing for IPQualityScore scanner.")
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

func (s *ScannerImpl) ScanTarget(target jobEntities.Target, timeout, retries uint64) ([]byte, error) {
	var content []byte
	var err error

	switch target.Type {
	case jobEntities.HOST_TYPE_CIDR:
		content, err = s.scanIP(target.Host)
	case jobEntities.HOST_TYPE_URL:
		content, err = s.scanURL(target.Host)
	case jobEntities.HOST_TYPE_DOMAIN:
		content, err = s.scanURL(target.Host)
	case jobEntities.HOST_TYPE_EMAIL:
		content, err = s.scanEmail(target.Host)
	default:
		return nil, errors.New("unsupported host type by VirusTotal")
	}

	return content, err
}
