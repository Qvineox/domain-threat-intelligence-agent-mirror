package test

import (
	"domain-threat-intelligence-agent/cmd/core/entities/jobEntities"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestJob(t *testing.T) {
	t.Run("open source scan job tasks calculation", func(t *testing.T) {
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

		tasks := job.CalculateTargets()

		require.Len(t, tasks, 7)

		require.Equal(t, tasks[0].Target, "10.10.20.10")
		require.Equal(t, tasks[0].Type, jobEntities.HOST_TYPE_CIDR)
		require.Equal(t, tasks[0].Provider, jobEntities.OSS_PROVIDER_IP_QUALITY_SCORE)

		require.Equal(t, tasks[1].Target, "10.10.20.10")
		require.Equal(t, tasks[1].Type, jobEntities.HOST_TYPE_CIDR)
		require.Equal(t, tasks[1].Provider, jobEntities.OSS_PROVIDER_VIRUS_TOTAL)

		require.Equal(t, tasks[2].Target, "10.10.20.10")
		require.Equal(t, tasks[2].Type, jobEntities.HOST_TYPE_CIDR)
		require.Equal(t, tasks[2].Provider, jobEntities.OSS_PROVIDER_SHODAN)

		require.Equal(t, tasks[6].Target, "lysak.yaroslav00@yandex.ru")
		require.Equal(t, tasks[6].Type, jobEntities.HOST_TYPE_EMAIL)
		require.Equal(t, tasks[6].Provider, jobEntities.OSS_PROVIDER_IP_QUALITY_SCORE)
	})

}
