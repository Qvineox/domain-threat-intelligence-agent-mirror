package ipQualityScore

type apiError struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	RequestId string `json:"request_id"`
}
