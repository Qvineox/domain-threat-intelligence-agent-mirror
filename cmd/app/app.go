package app

import (
	"domain-threat-intelligence-agent/api/grpc/servers"
	"domain-threat-intelligence-agent/cmd/core/services"
	"domain-threat-intelligence-agent/cmd/oss/crowdSec"
	"domain-threat-intelligence-agent/cmd/oss/ipQualityScore"
	"domain-threat-intelligence-agent/cmd/oss/shodan"
	"domain-threat-intelligence-agent/cmd/oss/virusTotal"
	"domain-threat-intelligence-agent/configs"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"log/slog"
	"net"
	"os"
	"path/filepath"
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

	var gRPCServer *grpc.Server

	if config.GRPCServer.UseTLS {
		creds, err := getTLSCredentials()
		if err != nil {
			slog.Error("failed to start secure grpc server: " + err.Error())
			panic(err)
		}

		gRPCServer = grpc.NewServer(grpc.Creds(creds))
	} else {
		gRPCServer = grpc.NewServer()
	}

	jobService := services.NewOpenSourceScannerImpl(
		virusTotal.NewScannerImpl(config.OSSProviders.VirusTotalAPIKey, config.HTTPClients.Proxy),
		ipQualityScore.NewScannerImpl(config.OSSProviders.IPQualityScoreAPIKey, config.HTTPClients.Proxy),
		shodan.NewScannerImpl(config.OSSProviders.ShodanAPIKey, config.HTTPClients.Proxy),
		crowdSec.NewScannerImpl(config.OSSProviders.CrowdSecAPIKey, config.HTTPClients.Proxy),
		nil,
	)

	servers.AddJobsServer(gRPCServer, jobService)

	err = gRPCServer.Serve(listener)
	if err != nil {
		slog.Error("failed to start grpc server: " + err.Error())
		panic(err)
	}

	return nil
}

func getTLSCredentials() (credentials.TransportCredentials, error) {
	currentDir, err := os.Getwd()
	if err != nil {
		slog.Error(err.Error())
		return nil, err
	}

	certPath := filepath.Join(currentDir, "tls", "cert.crt")
	keyPath := filepath.Join(currentDir, "tls", "cert.key")

	cr, err := credentials.NewServerTLSFromFile(certPath, keyPath)
	if err != nil {
		slog.Error("failed to create credentials: " + err.Error())
		return nil, err
	}

	return cr, nil
}
