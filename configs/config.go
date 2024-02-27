package configs

import (
	"github.com/ilyakaznacheev/cleanenv"
	"log/slog"
	"os"
	"path/filepath"
)

type StaticConfig struct {
	GRPCServer struct {
		Host string `env-required:"true" env:"grpc_host" json:"host"`
		Port uint64 `env-required:"true" env:"grpc_port" json:"port"`
	} `json:"grpc_server"`

	HTTPClients struct {
		Proxy string `env:"http_proxy" json:"proxy"`
	} `json:"http_clients"`

	OSSProviders struct {
		VirusTotalAPIKey     string `env:"oss_vt_apikey" json:"vt_apikey"`
		IPQualityScoreAPIKey string `env:"oss_ipqs_apikey" json:"ipqs_apikey"`
		ShodanAPIKey         string `env:"oss_shodan_apikey" json:"shodan_apikey"`
		CrowdSecAPIKey       string `env:"oss_crowdsec_apikey" json:"crowdsec_apikey"`
		IPWhoIsAPIKey        string `env:"oss_ipwhois_apikey" json:"ipwhois_apikey"`
	} `json:"oss_providers"`
}

func NewStaticConfig() (StaticConfig, error) {
	slog.Info("loading static configuration...")

	var cfg StaticConfig

	currentDir, err := os.Getwd()
	if err != nil {
		return StaticConfig{}, err
	}

	// if config file not find tries to get configuration parameters from environment
	err = cleanenv.ReadConfig(filepath.Join(currentDir, "configs", "config.static.json"), &cfg)
	if err != nil {
		slog.Warn("config file not found, reading environment...")
		err = cleanenv.ReadEnv(&cfg)
		if err != nil {
			return StaticConfig{}, err
		}
	}

	slog.Info("static configuration loaded")
	return cfg, nil
}
