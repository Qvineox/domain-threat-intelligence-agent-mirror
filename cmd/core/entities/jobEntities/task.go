package jobEntities

import (
	"domain-threat-intelligence-agent/cmd/core/entities/scanEntities"
)

type OSSTask struct {
	Target   Target
	ScanType scanEntities.ScanType
	Provider SupportedOSSProvider
}

type SupportedOSSProvider uint64

const (
	OSS_PROVIDER_VIRUS_TOTAL SupportedOSSProvider = iota
	OSS_PROVIDER_IP_QUALITY_SCORE
	OSS_PROVIDER_CROWD_SEC
	OSS_PROVIDER_SHODAN
	OSS_PROVIDER_IP_WHO_IS
)

//var SupportedByVirusTotal = []TargetType{HOST_TYPE_CIDR, HOST_TYPE_DOMAIN}
//var SupportedByIPQualityScore = []TargetType{HOST_TYPE_CIDR, HOST_TYPE_URL, HOST_TYPE_EMAIL}
//var SupportedByShodan = []TargetType{HOST_TYPE_CIDR}
//var SupportedByIPWhoIS = []TargetType{HOST_TYPE_CIDR}
//var SupportedByCrowdSec = []TargetType{HOST_TYPE_CIDR, HOST_TYPE_URL, HOST_TYPE_DOMAIN}

// NewOSSTasks returns tasks extruded from 1 target with every provided and supported opensource provider
func NewOSSTasks(target Target, providers []SupportedOSSProvider) []OSSTask {
	tasks := make([]OSSTask, 0)

	for _, p := range providers {
		scanType := scanEntities.SCAN_TYPE_UNKNOWN

		switch p {
		case OSS_PROVIDER_VIRUS_TOTAL:
			switch target.Type {
			case HOST_TYPE_CIDR:
				scanType = scanEntities.SCAN_TYPE_OSS_VT_IP
				break
			case HOST_TYPE_DOMAIN:
				scanType = scanEntities.SCAN_TYPE_OSS_VT_DOMAIN
				break
			//case HOST_TYPE_URL:
			//	scanType = scanEntities.SCAN_TYPE_OSS_VT_URL
			//case HOST_TYPE_EMAIL:
			default:
				continue
			}
		case OSS_PROVIDER_IP_QUALITY_SCORE:
			switch target.Type {
			case HOST_TYPE_CIDR:
				scanType = scanEntities.SCAN_TYPE_OSS_IPQS_IP
				break
			//case HOST_TYPE_DOMAIN:
			case HOST_TYPE_URL:
				scanType = scanEntities.SCAN_TYPE_OSS_IPQS_URL
				break
			case HOST_TYPE_EMAIL:
				scanType = scanEntities.SCAN_TYPE_OSS_IPQS_EMAIL
				break
			default:
				continue
			}
		case OSS_PROVIDER_SHODAN:
			switch target.Type {
			case HOST_TYPE_CIDR:
				scanType = scanEntities.SCAN_TYPE_OSS_SHODAN_IP
				break
			//case HOST_TYPE_DOMAIN:
			//case HOST_TYPE_URL:
			//case HOST_TYPE_EMAIL:
			default:
				continue
			}
		case OSS_PROVIDER_IP_WHO_IS:
			switch target.Type {
			case HOST_TYPE_CIDR:
				scanType = scanEntities.SCAN_TYPE_OSS_IPWH_IP
				break
			//case HOST_TYPE_DOMAIN:
			//case HOST_TYPE_URL:
			//case HOST_TYPE_EMAIL:
			default:
				continue
			}
		case OSS_PROVIDER_CROWD_SEC:
			switch target.Type {
			case HOST_TYPE_CIDR:
				scanType = scanEntities.SCAN_TYPE_OSS_CS_IP
				break
			//case HOST_TYPE_DOMAIN:
			//case HOST_TYPE_URL:
			//case HOST_TYPE_EMAIL:
			default:
				continue
			}
		default:
			continue
		}

		if scanType != scanEntities.SCAN_TYPE_UNKNOWN {
			tasks = append(tasks, OSSTask{
				Target: Target{
					Host: target.Host,
					Type: target.Type,
				},
				ScanType: scanType,
				Provider: p,
			})
		}
	}

	return tasks
}
