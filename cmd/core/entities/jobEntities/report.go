package jobEntities

import "domain-threat-intelligence-agent/cmd/core/entities/scanEntities"

type TargetAuditMessage struct {
	Target   Target                `json:"target"`
	ScanType scanEntities.ScanType `json:"scan_type"`
	Content  []byte                `json:"content"`
}

type TargetOSAuditError struct {
	Target   Target                `json:"target"`
	ScanType scanEntities.ScanType `json:"scan_type"`
	Error    error                 `json:"error"`
}
