package main

import (
	"domain-threat-intelligence-agent/cmd/app"
	"domain-threat-intelligence-agent/configs"
)

func main() {
	// reading configuration
	staticCfg, err := configs.NewStaticConfig()
	if err != nil {
		panic(err)
		return
	}
	// starting the application
	err = app.StartApp(staticCfg)
	if err != nil {
		panic(err)
		return
	}

	return
}
