package test

import (
	"context"
	"domain-threat-intelligence-agent/cmd/core"
	"domain-threat-intelligence-agent/cmd/core/entities"
	"domain-threat-intelligence-agent/cmd/core/entities/jobEntities"
	"domain-threat-intelligence-agent/cmd/core/services"
	"domain-threat-intelligence-agent/cmd/oss/virusTotal"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestScanners(t *testing.T) {
	//s := services.OpenSourceScannerImpl{
	//
	//}

	var scanner core.IProviderScanner

	t.Run("provider scanner creation", func(t *testing.T) {
		scanner = virusTotal.NewScannerImpl("", "")

		require.NotNil(t, scanner)
		require.False(t, scanner.IsActive())

		scanner = virusTotal.NewScannerImpl("test_api_key", "")

		require.NotNil(t, scanner)
		require.True(t, scanner.IsActive())

		scanner = virusTotal.NewScannerImpl("test_api_key", "https://proxy.example.com:1234")

		require.NotNil(t, scanner)
		require.True(t, scanner.IsActive())
	})

	t.Run("provider scanner config change", func(t *testing.T) {
		var err error

		err = scanner.SetConfig(entities.ScannerConfig{
			BaseURL:           "",
			APIKey:            "test_api_key",
			MinuteQueryLimit:  1,
			DailyQueryLimit:   1,
			MonthlyQueryLimit: 1,
		})

		require.Error(t, err)

		err = scanner.SetConfig(entities.ScannerConfig{
			BaseURL:           "test_url",
			APIKey:            "",
			MinuteQueryLimit:  1,
			DailyQueryLimit:   1,
			MonthlyQueryLimit: 1,
		})

		require.Error(t, err)

		err = scanner.SetConfig(entities.ScannerConfig{
			BaseURL:           "test_url",
			APIKey:            "test_api_key",
			MinuteQueryLimit:  1,
			DailyQueryLimit:   0,
			MonthlyQueryLimit: 1,
		})

		require.Error(t, err)

		err = scanner.SetConfig(entities.ScannerConfig{
			BaseURL:           "test_url",
			APIKey:            "test_api_key",
			MinuteQueryLimit:  1,
			DailyQueryLimit:   1,
			MonthlyQueryLimit: 1,
		})

		require.NoError(t, err)
		require.True(t, scanner.IsActive())

	})

	t.Run("provider scanner config read", func(t *testing.T) {
		const proxyURL = "https://proxy.example.com:1234"
		const apiKey = "test_api_key"

		scanner = virusTotal.NewScannerImpl(apiKey, proxyURL)
		require.NotNil(t, scanner)

		config := scanner.GetConfig()

		require.NotNil(t, config)
		require.Equal(t, config.APIKey, apiKey)
		require.Equal(t, config.ProxyURL, proxyURL)
	})

	var vt, ipqs, shd, cs, ipwh core.IProviderScanner

	t.Run("check different providers", func(t *testing.T) {
		var err error

		const apiKey = ""
		const proxyURL = ""

		vt = virusTotal.NewScannerImpl(apiKey, proxyURL)
		require.NotNil(t, vt)

		config := vt.GetConfig()
		require.Equal(t, config.APIKey, apiKey)
		require.Equal(t, config.ProxyURL, proxyURL)

		ipqs = virusTotal.NewScannerImpl(apiKey, proxyURL)
		require.NotNil(t, ipqs)

		config = ipqs.GetConfig()
		require.Equal(t, config.APIKey, apiKey)
		require.Equal(t, config.ProxyURL, proxyURL)

		shd = virusTotal.NewScannerImpl(apiKey, proxyURL)
		require.NotNil(t, shd)

		config = shd.GetConfig()
		require.Equal(t, config.APIKey, apiKey)
		require.Equal(t, config.ProxyURL, proxyURL)

		cs = virusTotal.NewScannerImpl(apiKey, proxyURL)
		require.NoError(t, err)

		config = cs.GetConfig()
		require.Equal(t, config.APIKey, apiKey)
		require.Equal(t, config.ProxyURL, proxyURL)

		ipwh = virusTotal.NewScannerImpl(apiKey, proxyURL)
		require.NotNil(t, shd)

		config = ipwh.GetConfig()
		require.Equal(t, config.APIKey, apiKey)
		require.Equal(t, config.ProxyURL, proxyURL)
	})

	var fullScanner core.IOpenSourceScanner

	t.Run("full scanner creation", func(t *testing.T) {
		fullScanner = services.NewOpenSourceScannerImpl(vt, ipqs, shd, cs, ipwh)
		require.NotNil(t, fullScanner)
	})

	t.Run("tasks execution with no api keys", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		var job = jobEntities.OpenSourceScanJob{
			Job: jobEntities.Job{
				UUID:       "test",
				Type:       jobEntities.JOB_TYPE_OSS,
				Status:     jobEntities.JOB_STATUS_STARTING,
				Priority:   jobEntities.JOB_PRIORITY_LOW,
				Weight:     10,
				StartedAt:  nil,
				FinishedAt: nil,
				Targets: []jobEntities.Target{
					{Host: "10.10.10.10/32", Type: jobEntities.HOST_TYPE_CIDR},
					{Host: "10.10.10.20/32", Type: jobEntities.HOST_TYPE_CIDR},
					{Host: "10.10.10.30/32", Type: jobEntities.HOST_TYPE_CIDR},
					{Host: "10.10.20.10/32", Type: jobEntities.HOST_TYPE_CIDR},
					{Host: "10.10.20.20/32", Type: jobEntities.HOST_TYPE_CIDR},
					{Host: "10.10.30.10/32", Type: jobEntities.HOST_TYPE_CIDR},
					{Host: "ya.ru", Type: jobEntities.HOST_TYPE_DOMAIN},
					{Host: "mirea.ru", Type: jobEntities.HOST_TYPE_DOMAIN},
					{Host: "lysak.yaroslav00@yandex.ru", Type: jobEntities.HOST_TYPE_EMAIL},
				},
				Exceptions: []jobEntities.Target{
					{Host: "10.10.10.0/24", Type: jobEntities.HOST_TYPE_CIDR},
					{Host: "10.10.20.20/32", Type: jobEntities.HOST_TYPE_CIDR},
					{Host: "ya.ru", Type: jobEntities.HOST_TYPE_DOMAIN},
					{Host: "mirea.ru", Type: jobEntities.HOST_TYPE_DOMAIN},
				},
				Timings: jobEntities.Timings{
					Timeout: 10000,
					Delay:   200,
					Retries: 3,
				},
			},
			Providers: []jobEntities.SupportedOSSProvider{
				jobEntities.OSS_PROVIDER_IP_QUALITY_SCORE,
				jobEntities.OSS_PROVIDER_VIRUS_TOTAL,
				jobEntities.OSS_PROVIDER_SHODAN,
			},
		}

		r := make(chan []byte, 1000)
		e := make(chan error, 1000)

		tasks := job.CalculateTargets()
		require.Len(t, tasks, 7)

		fullScanner.StartTasksExecution(ctx, tasks, job.Timings, r, e)

		var elapsedTasks, totalTasks = 0, len(tasks)

		for {
			select {
			case _, ok := <-r:
				if !ok {
					r = nil
					break
				}

				elapsedTasks++
			case msg, ok := <-e:
				if !ok {
					e = nil
					break
				}

				require.Equal(t, msg.Error(), "selected scanner not found or not active")
				elapsedTasks++
			}

			if elapsedTasks == totalTasks {
				break
			}
		}

		require.Equal(t, elapsedTasks, totalTasks)
		cancel()
	})
}