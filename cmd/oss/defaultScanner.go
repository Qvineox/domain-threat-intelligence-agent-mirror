package oss

import (
	"domain-threat-intelligence-agent/cmd/core/entities"
	"domain-threat-intelligence-agent/cmd/core/entities/jobEntities"
	"errors"
	"net/http"
)

type OpenSourceScanner struct {
	Config entities.ScannerConfig
	Client *http.Client
}

func (s *OpenSourceScanner) GetConfig() entities.ScannerConfig {
	return s.Config
}

func (s *OpenSourceScanner) SetConfig(config entities.ScannerConfig) error {
	if len(config.Host) == 0 {
		return errors.New("host not defined")
	}

	if len(config.APIKey) == 0 {
		return errors.New("API key not defined")
	}

	if config.DayQueryLimit == 0 || config.HourQueryLimit == 0 {
		return errors.New("limits must be defined")
	}

	s.Config = config

	return nil
}

func (s *OpenSourceScanner) ScanTarget(target jobEntities.Target, timeout uint64, retries uint64) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (s *OpenSourceScanner) IsActive() bool {
	return s.Client != nil && s.Config.Host != "" && s.Config.APIKey != ""
}
