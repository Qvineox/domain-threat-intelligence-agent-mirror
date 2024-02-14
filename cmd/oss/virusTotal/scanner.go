package virusTotal

import (
	"domain-threat-intelligence-agent/cmd/oss"
)

type Scanner struct {
	oss.OpenSourceScanner
}

func (s *Scanner) ScanTarget(target string) ([]byte, error) {
	//TODO implement me
	panic("implement me")
}
