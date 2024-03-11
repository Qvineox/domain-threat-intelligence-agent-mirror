package jobEntities

type Target struct {
	Host string     `json:"host"`
	Type TargetType `json:"type"`
}
