package jobEntities

import (
	"slices"
)

type OSSTarget struct {
	Target

	Provider SupportedOSSProvider
}

type TargetType uint64

const (
	HOST_TYPE_CIDR TargetType = iota
	HOST_TYPE_DOMAIN
	HOST_TYPE_URL
	HOST_TYPE_EMAIL
)

type SupportedOSSProvider uint64

const (
	OSS_PROVIDER_VIRUS_TOTAL SupportedOSSProvider = iota
	OSS_PROVIDER_IP_QUALITY_SCORE
	OSS_PROVIDER_CROWD_SEC
	OSS_PROVIDER_SHODAN
	OSS_PROVIDER_IP_WHO_IS
)

var SupportedByVirusTotal = []TargetType{HOST_TYPE_CIDR, HOST_TYPE_DOMAIN}
var SupportedByIPQualityScore = []TargetType{HOST_TYPE_CIDR, HOST_TYPE_URL, HOST_TYPE_EMAIL}
var SupportedByShodan = []TargetType{HOST_TYPE_CIDR}
var SupportedByIPWhoIS = []TargetType{HOST_TYPE_CIDR}
var SupportedByCrowdSec = []TargetType{HOST_TYPE_CIDR, HOST_TYPE_URL, HOST_TYPE_DOMAIN}

func NewOSSTarget(target Target, providers []SupportedOSSProvider) []OSSTarget {
	tasks := make([]OSSTarget, 0)

	for _, p := range providers {
		switch p {
		case OSS_PROVIDER_VIRUS_TOTAL:
			if !slices.Contains(SupportedByVirusTotal, target.Type) {
				continue
			}
		case OSS_PROVIDER_IP_QUALITY_SCORE:
			if !slices.Contains(SupportedByIPQualityScore, target.Type) {
				continue
			}
		case OSS_PROVIDER_SHODAN:
			if !slices.Contains(SupportedByShodan, target.Type) {
				continue
			}
		case OSS_PROVIDER_IP_WHO_IS:
			if !slices.Contains(SupportedByIPWhoIS, target.Type) {
				continue
			}
		case OSS_PROVIDER_CROWD_SEC:
			if !slices.Contains(SupportedByCrowdSec, target.Type) {
				continue
			}
		default:
			continue
		}

		tasks = append(tasks, OSSTarget{
			Target: Target{
				Host: target.Host,
				Type: target.Type,
			},
			Provider: p,
		})
	}

	return tasks
}

type TargetOSAuditMessage struct {
	Target   Target               `json:"target"`
	Provider SupportedOSSProvider `json:"provider"`
	Content  []byte               `json:"content"`
}

type TargetOSAuditError struct {
	Target   Target               `json:"target"`
	Provider SupportedOSSProvider `json:"provider"`
	Error    error                `json:"error"`
}
