package shodan

import (
	"domain-threat-intelligence-agent/cmd/core/entities"
	"domain-threat-intelligence-agent/cmd/core/entities/jobEntities"
	"domain-threat-intelligence-agent/cmd/oss"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
)

const baseURL = "https://cti.api.crowdsec.net/v2"
const minuteLimit = 5
const dailyLimit = 50
const monthlyLimit = 50

type ScannerImpl struct {
	oss.OpenSourceScanner
}

func NewScannerImpl(apiKey, proxy string) (*ScannerImpl, error) {
	client := &http.Client{}

	if len(apiKey) == 0 {
		slog.Warn("api key missing for shodan scanner.")
	}

	if len(proxy) > 0 {
		proxyUrl, err := url.Parse(proxy)
		if err != nil {
			return nil, err
		}

		client.Transport = &http.Transport{Proxy: http.ProxyURL(proxyUrl)}
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
	}, nil
}

func (s *ScannerImpl) ScanTarget(target jobEntities.Target, timeout, retries uint64) ([]byte, error) {
	var virusTotalScanMockup = fmt.Sprintf("this is CrowdSec scan report mockup string for target: %s with type %d", target.Host, target.Type)

	return []byte(virusTotalScanMockup), nil
}
