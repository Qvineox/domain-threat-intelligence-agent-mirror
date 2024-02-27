package crowdSec

type apiError struct {
	Message string `json:"message"`
	Errors  string `json:"errors"`
}
