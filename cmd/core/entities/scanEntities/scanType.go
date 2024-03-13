package scanEntities

type ScanType uint64

const (
	SCAN_TYPE_UNKNOWN         ScanType = 0
	SCAN_TYPE_OSS_VT_IP                = 101
	SCAN_TYPE_OSS_VT_DOMAIN            = 102
	SCAN_TYPE_OSS_VT_URL               = 103
	SCAN_TYPE_OSS_IPQS_IP              = 201
	SCAN_TYPE_OSS_IPQS_DOMAIN          = 202
	SCAN_TYPE_OSS_IPQS_URL             = 203
	SCAN_TYPE_OSS_IPQS_EMAIL           = 204
	SCAN_TYPE_OSS_SHODAN_IP            = 301
	SCAN_TYPE_OSS_CS_IP                = 401
	SCAN_TYPE_OSS_IPWH_IP              = 501
)
