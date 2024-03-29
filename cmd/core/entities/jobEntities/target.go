package jobEntities

type Target struct {
	Host string     `json:"host"`
	Type TargetType `json:"type"`
}

type TargetType uint64

const (
	HOST_TYPE_CIDR TargetType = iota
	HOST_TYPE_DOMAIN
	HOST_TYPE_URL
	HOST_TYPE_EMAIL
)
