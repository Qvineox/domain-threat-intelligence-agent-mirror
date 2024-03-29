package protoServices

import (
	"context"
	"domain-threat-intelligence-agent/cmd/core"
	"domain-threat-intelligence-agent/cmd/core/entities/jobEntities"
	"errors"
	"fmt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"log/slog"
	"net"
	"sync"
)

type JobsServerImpl struct {
	Service core.IOpenSourceScanner
}

func (s *JobsServerImpl) StartOSS(pj *Job, stream Jobs_StartOSSServer) error {
	//startTime := time.Now()

	slog.Info(fmt.Sprintf("starting OSS job '%s'", pj.Meta.Uuid))
	var totalTasks, elapsedTasks, successfulTasks uint64 = 0, 0, 0

	// ctx should be used to stop scanning if stream interrupted by user client
	ctx, cancel := context.WithCancel(context.Background())

	returnChannel := make(chan jobEntities.TargetOSAuditMessage, 1000) // hardcoded restriction!
	errorChannel := make(chan jobEntities.TargetOSAuditError, 1000)    // hardcoded restriction!

	switch pj.Meta.Type {
	case JobType_JOB_TYPE_OSS:
		job, err := NewOpenSourceScanJobFromProto(pj)
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
	err := stream.SetHeader(metadata.Pairs("job_type", "oss"))
	if err != nil {
		cancel()
		return status.Error(codes.Internal, "failed to set job type headers")
	}

listenJobs:
	for {
		select {
		case <-stream.Context().Done():
			slog.Warn(fmt.Sprintf("job %s cancelled from context", pj.Meta.Uuid))

			cancel()

			break listenJobs
		case msg, ok := <-returnChannel:
			if !ok {
				returnChannel = nil
				break
			}

			wg.Add(1)

			err = stream.Send(&TargetAuditReport{
				TasksLeft:    totalTasks - elapsedTasks - 1,
				IsSuccessful: true,
				Target:       newProtoFromTarget(msg.Target),
				Provider:     OSSProvider(msg.Provider),
				Content:      msg.Content,
			})
			elapsedTasks++
			successfulTasks++

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

			err = stream.Send(&TargetAuditReport{
				TasksLeft:    totalTasks - elapsedTasks - 1,
				IsSuccessful: false,
				Target:       newProtoFromTarget(msg.Target),
				Provider:     OSSProvider(msg.Provider),
				Content:      []byte(msg.Error.Error()),
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
	slog.Info(fmt.Sprintf("finished job '%s' (completed %d out of %d tasks)", pj.Meta.Uuid, successfulTasks, totalTasks))

	//stream.SetTrailer(metadata.Pairs(
	//	"successful_tasks", strconv.FormatUint(successfulTasks, 10),
	//	"elapsed_tasks", strconv.FormatUint(elapsedTasks, 10),
	//	"total_tasks", strconv.FormatUint(totalTasks, 10),
	//	"time_taken", strconv.FormatInt(int64(time.Now().Sub(startTime).Truncate(time.Second)), 10),
	//	"job_uuid", pj.Meta.Uuid,
	//))

	// ref: https://www.geeksforgeeks.org/time-time-truncate-function-in-golang-with-examples/

	return nil
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

func newProtoFromTarget(target jobEntities.Target) *Target {
	return &Target{
		Host: target.Host,
		Type: HostType(target.Type),
	}
}

func newTimingsFromProto(timings *Timings) jobEntities.Timings {
	return jobEntities.Timings{
		Timeout: timings.Timeout,
		Delay:   timings.Delay,
		Retries: timings.Retries,
	}
}
