package services

import (
	"context"
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

func NewOpenSourceScannerImpl(vt, ipqs, shd, cs, ipwh core.IProviderScanner) *OpenSourceScannerImpl {
	return &OpenSourceScannerImpl{vt: vt, ipqs: ipqs, shd: shd, cs: cs, ipwh: ipwh}
}

func (s *OpenSourceScannerImpl) StartTasksExecution(ctx context.Context, tasks []jobEntities.OSSTask, timings jobEntities.Timings, c chan jobEntities.TargetAuditMessage, e chan jobEntities.TargetOSAuditError) {
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

	go startScans(ctx, s.vt, vtTasks, timings, c, e, wg)
	go startScans(ctx, s.ipqs, ipqsTasks, timings, c, e, wg)
	go startScans(ctx, s.shd, shdTasks, timings, c, e, wg)
	go startScans(ctx, s.cs, csTasks, timings, c, e, wg)
	go startScans(ctx, s.ipwh, ipwhTasks, timings, c, e, wg)

	wg.Wait()

	close(c)
}

func startScans(ctx context.Context, scanner core.IProviderScanner, tasks []jobEntities.OSSTask, timings jobEntities.Timings, c chan jobEntities.TargetAuditMessage, e chan jobEntities.TargetOSAuditError, wg *sync.WaitGroup) {
	if tasks == nil || len(tasks) == 0 {
		wg.Done()
		return
	}

	if scanner == nil || !scanner.IsActive() {
		slog.Warn(fmt.Sprintf("scan tasks (%d) cancelled: scanner not found or not active", len(tasks)))

		for _, t := range tasks {
			e <- jobEntities.TargetOSAuditError{
				Target:   t.Target,
				ScanType: t.ScanType,
				Error:    errors.New("selected scanner not found or not active"),
			}
		}

		wg.Done()
		return
	}

taskProcessing:
	for _, t := range tasks {
		select {
		case <-ctx.Done():
			slog.Warn("scanning cancelled from job context")
			break taskProcessing
		default:
			bytes, err := scanner.ScanTarget(t.Target, timings.Timeout, timings.Retries)
			if err != nil {
				slog.Error(fmt.Sprintf("failed to scan target '%s' via '%d': %s", t.Target.Host, t.ScanType, err.Error()))
				e <- jobEntities.TargetOSAuditError{
					ScanType: t.ScanType,
					Target:   t.Target,
					Error:    err,
				}
			} else {
				slog.Info(fmt.Sprintf("scan completed '%s' via '%d', sending...", t.Target.Host, t.ScanType))
				c <- jobEntities.TargetAuditMessage{
					ScanType: t.ScanType,
					Target:   t.Target,
					Content:  bytes,
				}
			}
		}

		time.Sleep(time.Duration(timings.Delay) * time.Millisecond) // delay
	}

	wg.Done()
}

func groupTasksByProvider(tasks []jobEntities.OSSTask) (vt, ipqs, shd, cs, ipwh []jobEntities.OSSTask) {
	for _, t := range tasks {
		switch t.Provider {
		case jobEntities.OSS_PROVIDER_VIRUS_TOTAL:
			vt = append(vt, t)
		case jobEntities.OSS_PROVIDER_IP_QUALITY_SCORE:
			ipqs = append(ipqs, t)
		case jobEntities.OSS_PROVIDER_CROWD_SEC:
			cs = append(cs, t)
		case jobEntities.OSS_PROVIDER_SHODAN:
			shd = append(shd, t)
		case jobEntities.OSS_PROVIDER_IP_WHO_IS:
			ipwh = append(ipwh, t)
		default:
			continue
		}
	}

	return vt, ipqs, shd, cs, ipwh
}
