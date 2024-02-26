package servers

import (
	"domain-threat-intelligence-agent/api/grpc/protoServices"
	"domain-threat-intelligence-agent/cmd/core"
	"google.golang.org/grpc"
)

func AddJobsServer(server *grpc.Server, service core.IOpenSourceScanner) {
	protoServices.RegisterJobsServer(server, &protoServices.JobsServerImpl{
		Service: service,
	})
}
