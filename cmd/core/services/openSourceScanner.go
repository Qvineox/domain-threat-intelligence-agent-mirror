package services

import (
	"domain-threat-intelligence-agent/cmd/core"
	"domain-threat-intelligence-agent/cmd/core/entities/jobEntities"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

type OpenSourceScannerImpl struct {
	vt   core.IProviderScanner // virusTotal
	ipqs core.IProviderScanner // ipQualityScore
	shd  core.IProviderScanner // shodan
	cs   core.IProviderScanner // crowdSec
	ipwh core.IProviderScanner // ipWhoIs
}

func (s *OpenSourceScannerImpl) StartTasksExecution(tasks []jobEntities.OSSTarget, timings jobEntities.Timings, c chan []byte, e chan error) {
	// default values for timing (abuse restrains)
	{
		if timings.Delay < 100 {
			timings.Delay = 100
		}
		if timings.Timeout < 2000 {
			timings.Timeout = 2000
		}
		if timings.Retries < 1 {
			timings.Retries = 1
		}
	}

	vtTasks, ipqsTasks, shdTasks, csTasks, ipwhTasks := groupTasksByProvider(tasks)

	wg := &sync.WaitGroup{}
	wg.Add(5)

	go startScans(s.vt, vtTasks, timings, c, e, wg)
	go startScans(s.ipqs, ipqsTasks, timings, c, e, wg)
	go startScans(s.shd, shdTasks, timings, c, e, wg)
	go startScans(s.cs, csTasks, timings, c, e, wg)
	go startScans(s.ipwh, ipwhTasks, timings, c, e, wg)

	wg.Wait()

	close(c)
}

func startScans(scanner core.IProviderScanner, tasks []jobEntities.Target, timings jobEntities.Timings, c chan []byte, e chan error, wg *sync.WaitGroup) {
	if tasks == nil || len(tasks) == 0 {
		wg.Done()
		return
	}

	if scanner == nil || !scanner.IsActive() {
		for range tasks {
			e <- errors.New("selected scanner not found")
		}

		wg.Done()
		return
	}

	if tasks == nil || len(tasks) == 0 {
		for range tasks {
			e <- errors.New("no tasks provided")
		}

		wg.Done()
		return
	}

	for _, t := range tasks {
		bytes, err := scanner.ScanTarget(t, timings.Timeout, timings.Retries)
		if err != nil {
			slog.Error(fmt.Sprintf("failed to scan target '%s' via '%s'", t.Host, scanner.GetConfig().Host))
			e <- err

			continue
		}

		c <- bytes

		time.Sleep(time.Duration(timings.Delay) * time.Millisecond) // delay
	}

	wg.Done()
}

func groupTasksByProvider(tasks []jobEntities.OSSTarget) (vt, ipqs, shd, cs, ipwh []jobEntities.Target) {
	for _, t := range tasks {
		switch t.Provider {
		case jobEntities.OSS_PROVIDER_VIRUS_TOTAL:
			vt = append(vt, t.Target)
		case jobEntities.OSS_PROVIDER_IP_QUALITY_SCORE:
			ipqs = append(ipqs, t.Target)
		case jobEntities.OSS_PROVIDER_CROWD_SEC:
			cs = append(cs, t.Target)
		case jobEntities.OSS_PROVIDER_SHODAN:
			shd = append(shd, t.Target)
		case jobEntities.OSS_PROVIDER_IP_WHO_IS:
			ipwh = append(ipwh, t.Target)
		default:
			continue
		}
	}

	return vt, ipqs, shd, cs, ipwh
}
