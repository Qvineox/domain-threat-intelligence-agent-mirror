package protoServices

import (
	"context"
	"domain-threat-intelligence-agent/cmd/core"
	"domain-threat-intelligence-agent/cmd/core/entities/jobEntities"
	"errors"
	"fmt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log/slog"
	"net"
	"sync"
)

type JobsServerImpl struct {
	Service core.IOpenSourceScanner
}

func (s *JobsServerImpl) StartJob(protoJob *Job, stream Jobs_StartJobServer) error {
	slog.Info(fmt.Sprintf("starting job '%x'", protoJob.Meta.Uuid))
	var totalTasks, elapsedTasks uint64 = 0, 0

	// ctx should be used to stop scanning if stream interrupted by user client
	ctx, cancel := context.WithCancel(context.Background())

	returnChannel := make(chan []byte, 1000) // hardcoded restriction!
	errorChannel := make(chan error, 1000)   // hardcoded restriction!

	switch protoJob.Meta.Type {
	case JobType_JOB_TYPE_OSS:
		job, err := NewOpenSourceScanJobFromProto(protoJob)
		if err != nil {
			cancel()

			return status.Error(codes.InvalidArgument, "could not create scanning job: "+err.Error())
		}

		tasks := job.CalculateTargets()
		totalTasks = uint64(len(tasks))

		go s.Service.StartTasksExecution(ctx, tasks, job.Timings, returnChannel, errorChannel)
	default:
		cancel()

		return status.Error(codes.InvalidArgument, "selected scanning job type not supported")
	}

	wg := &sync.WaitGroup{}

listenJobs:
	for {
		select {
		case <-stream.Context().Done():
			slog.Warn(fmt.Sprintf("job %s cancelled from context", protoJob.Meta.Uuid))

			cancel()

			break listenJobs
		case msg, ok := <-returnChannel:
			if !ok {
				returnChannel = nil
				break
			}

			wg.Add(1)

			err := stream.Send(&HostAuditReport{
				TasksLeft:    totalTasks - elapsedTasks - 1,
				Content:      msg,
				IsSuccessful: true,
			})
			elapsedTasks++

			if err != nil {
				slog.Error("failed to return message via stream: " + err.Error())
			}

			wg.Done()
		case msg, ok := <-errorChannel:
			if !ok {
				errorChannel = nil
				break
			}

			wg.Add(1)

			err := stream.Send(&HostAuditReport{
				TasksLeft:    totalTasks - elapsedTasks - 1,
				Content:      []byte(msg.Error()),
				IsSuccessful: false,
			})
			elapsedTasks++

			if err != nil {
				slog.Error("failed to return message via stream: " + err.Error())
			}

			wg.Done()
		}

		if elapsedTasks == totalTasks || returnChannel == nil {
			cancel()
			break
		}
	}

	wg.Wait()
	return nil
}

func (s *JobsServerImpl) TerminateJob(ctx context.Context, termination *JobTermination) (*None, error) {
	//TODO implement me
	panic("implement me")
}

func (s *JobsServerImpl) RetrieveQueue(ctx context.Context, none *None) (*Queue, error) {
	//TODO implement me
	panic("implement me")
}

func (s *JobsServerImpl) RetrieveQueueStatus(ctx context.Context, none *None) (*QueueStatus, error) {
	//TODO implement me
	panic("implement me")
}

func (s *JobsServerImpl) mustEmbedUnimplementedJobsServer() {
	//TODO implement me
	panic("implement me")
}

func NewOpenSourceScanJobFromProto(job *Job) (*jobEntities.OpenSourceScanJob, error) {
	if job.Meta == nil || job.Payload == nil || job.Directives == nil {
		return nil, errors.New("cannot create job. missing required element")
	}

	var exceptions = make([]jobEntities.Target, len(job.Payload.Exceptions))
	for _, v := range job.Payload.Exceptions {
		exceptions = append(exceptions, newTargetFromProto(v))
	}

	var targets = make([]jobEntities.Target, len(job.Payload.Targets))
	for _, v := range job.Payload.Targets {
		targets = append(targets, newTargetFromProto(v))
	}

	var providers = make([]jobEntities.SupportedOSSProvider, 0)
	if job.Directives.Oss == nil || len(job.Directives.Oss.Providers) == 0 {
		return nil, errors.New("cannot create job. missing open source providers")
	}

	for _, v := range job.Directives.Oss.Providers {
		providers = append(providers, jobEntities.SupportedOSSProvider(v))
	}

	j := jobEntities.OpenSourceScanJob{
		Job: jobEntities.Job{
			UUID:       job.Meta.Uuid,
			Type:       jobEntities.JobType(job.Meta.Type),
			Status:     jobEntities.JobStatus(job.Meta.Status),
			Priority:   jobEntities.JobPriority(job.Meta.Priority),
			Weight:     job.Meta.Weight,
			Targets:    targets,
			Exceptions: exceptions,
			Timings:    newTimingsFromProto(job.Directives.Oss.Timings),
		},
		Providers: providers,
	}

	return &j, nil
}

func getHostsFromCIDR(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// if net == 32 (no broadcast or network)
	if len(ips) <= 1 {
		return ips, nil
	}

	// remove network address and broadcast address
	return ips[1 : len(ips)-1], nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func newTargetFromProto(target *Target) jobEntities.Target {
	return jobEntities.Target{
		Host: target.GetHost(),
		Type: jobEntities.TargetType(target.GetType()),
	}
}

func newTimingsFromProto(timings *Timings) jobEntities.Timings {
	return jobEntities.Timings{
		Timeout: timings.Timeout,
		Delay:   timings.Delay,
		Retries: timings.Retries,
	}
}
