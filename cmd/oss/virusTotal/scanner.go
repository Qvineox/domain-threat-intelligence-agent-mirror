package virusTotal

import (
	"domain-threat-intelligence-agent/cmd/core"
	"domain-threat-intelligence-agent/cmd/core/entities/jobEntities"
)

type Scanner struct {
	core.IProviderScanner
}

func (s *Scanner) ScanTarget(target jobEntities.Target, timeout uint64, retries uint64) ([]byte, error) {
	//TODO implement me
	panic("implement me")
}
