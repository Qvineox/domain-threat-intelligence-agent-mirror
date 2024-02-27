package entities

type ScannerConfig struct {
	BaseURL string
	APIKey  string

	MinuteQueryLimit  uint64
	DailyQueryLimit   uint64
	MonthlyQueryLimit uint64

	ProxyURL string
}
