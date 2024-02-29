package oss

import (
	"domain-threat-intelligence-agent/cmd/core/entities"
	"domain-threat-intelligence-agent/cmd/core/entities/jobEntities"
	"errors"
	"net/http"
	"net/url"
)

type OpenSourceScanner struct {
	Config entities.ScannerConfig
	Client *http.Client
}

func (s *OpenSourceScanner) GetConfig() entities.ScannerConfig {
	return s.Config
}

func (s *OpenSourceScanner) SetConfig(config entities.ScannerConfig) error {
	if len(config.BaseURL) == 0 {
		return errors.New("host not defined")
	}

	if len(config.APIKey) == 0 {
		return errors.New("API key not defined")
	}

	if config.MonthlyQueryLimit == 0 || config.DailyQueryLimit == 0 || config.MinuteQueryLimit == 0 {
		return errors.New("limits must be defined")
	}

	if len(config.ProxyURL) > 0 {
		proxyUrl, err := url.Parse(config.ProxyURL)
		if err != nil {
			return err
		}

		if s.Client == nil {
			return errors.New("http client not found")
		}

		s.Client.Transport = &http.Transport{Proxy: http.ProxyURL(proxyUrl)}
	}

	s.Config = config

	return nil
}

func (s *OpenSourceScanner) GetProvider() jobEntities.SupportedOSSProvider {
	return 999
}

func (s *OpenSourceScanner) ScanTarget(target jobEntities.Target, timeout uint64, retries uint64) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (s *OpenSourceScanner) IsActive() bool {
	return s.Client != nil && s.Config.BaseURL != "" && s.Config.APIKey != ""
}
