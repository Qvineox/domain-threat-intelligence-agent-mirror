package core

import (
	"context"
	"domain-threat-intelligence-agent/cmd/core/entities"
	"domain-threat-intelligence-agent/cmd/core/entities/jobEntities"
)

// IOpenSourceScanner describes interface for composite scanner for multiple APIs
type IOpenSourceScanner interface {
	// StartTasksExecution ReceiveTasks accepts tasks list and a channel to return JSON binary stream.
	// This stream of audit reports that are sent back to main API via gRPC.
	StartTasksExecution(context.Context, []jobEntities.OSSTarget, jobEntities.Timings, chan []byte, chan error)
}

// IProviderScanner describes interface for single API provider scanner
type IProviderScanner interface {
	// GetConfig and SetConfig required to manage scanner config, so the scanner can authorize in provided service
	GetConfig() entities.ScannerConfig
	SetConfig(entities.ScannerConfig) error

	ScanTarget(target jobEntities.Target, timeout, retries uint64) ([]byte, error)

	IsActive() bool

	// Sign is needed to pass task data to requesting user. Contains task type and additional data
	Sign() []byte
}
