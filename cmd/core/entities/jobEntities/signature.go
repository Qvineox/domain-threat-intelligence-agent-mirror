package jobEntities

type Signature struct {
	Type     JobType              `json:"type"`
	Provider SupportedOSSProvider `json:"provider"` // depends on Type
}
