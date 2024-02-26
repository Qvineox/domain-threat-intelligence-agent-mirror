package jobEntities

import "time"

type Job struct {
	UUID string

	Type     JobType
	Status   JobStatus
	Priority JobPriority
	Weight   int64

	StartedAt  *time.Time
	FinishedAt *time.Time

	Targets    []Target
	Exceptions []Target

	Timings Timings
}

type JobType uint64
type JobStatus uint64
type JobPriority uint64

const (
	JOB_TYPE_OSS JobType = iota
	JOB_TYPE_NMAP
	JOB_TYPE_WHOIS
	JOB_TYPE_DNS
	JOB_TYPE_DISCOVERY
	JOB_TYPE_SPIDER
)

const (
	JOB_STATUS_PENDING   JobStatus = iota // not yet started
	JOB_STATUS_STARTING                   // calculating tasks, creating required structures
	JOB_STATUS_WORKING                    // executing tasks
	JOB_STATUS_FINISHING                  // clearing and sending data
	JOB_STATUS_DONE                       // job finished execution and saved
	JOB_STATUS_ERROR                      // job stopped with error from API or scanners (can be multiple errors, with threshold)
	JOB_STATUS_PANIC                      // internal exception
	JOB_STATUS_CANCELLED                  // job was cancelled by user
)

const (
	JOB_PRIORITY_CRITICAL JobPriority = iota // job must be executed instantly
	JOB_PRIORITY_HIGH                        // job must be executed after current (stack mode)
	JOB_PRIORITY_MEDIUM                      // job should be executed with higher priority
	JOB_PRIORITY_LOW                         // job should be executed lastly in order (queue mode)

)
