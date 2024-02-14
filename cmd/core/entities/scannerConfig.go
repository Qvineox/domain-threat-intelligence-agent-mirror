package entities

type ScannerConfig struct {
	Host   string
	APIKey string

	// HourQueryLimit sets a limit on amount of requests per hour
	HourQueryLimit uint64

	// DayQueryLimit sets a limit on amount of requests per day
	DayQueryLimit uint64

	// DelaySeconds sets a delay before every request
	DelaySeconds uint64
}
