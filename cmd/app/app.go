package app

import (
	"domain-threat-intelligence-agent/api/grpc/servers"
	"domain-threat-intelligence-agent/cmd/core/services"
	"domain-threat-intelligence-agent/cmd/oss/ipQualityScore"
	"domain-threat-intelligence-agent/cmd/oss/virusTotal"
	"domain-threat-intelligence-agent/configs"
	"fmt"
	"google.golang.org/grpc"
	"log/slog"
	"net"
	"strconv"
)

func StartApp(config configs.StaticConfig) error {
	slog.Info("application starting...")

	listener, err := net.Listen("tcp", net.JoinHostPort(config.GRPCServer.Host, strconv.FormatUint(config.GRPCServer.Port, 10)))
	if err != nil {
		slog.Error("failed to start listener: " + err.Error())
		panic(err)
	} else {
		slog.Info(fmt.Sprintf("network listener started on %s:%d", config.GRPCServer.Host, config.GRPCServer.Port))
	}

	gRPCServer := grpc.NewServer()

	jobService := services.NewOpenSourceScannerImpl(
		virusTotal.NewScannerImpl("test_key", ""),
		ipQualityScore.NewScannerImpl("test_key", ""),
		nil,
		nil,
		nil,
	)

	servers.AddJobsServer(gRPCServer, jobService)

	err = gRPCServer.Serve(listener)
	if err != nil {
		slog.Error("failed to start grpc server: " + err.Error())
		return err
	}

	return nil
}
