// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v4.25.3
// source: agent.proto

package protoServices

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// ConnectionClient is the client API for Connection Service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ConnectionClient interface {
	Hello(ctx context.Context, in *SecurityToken, opts ...grpc.CallOption) (*SecurityToken, error)
}

type connectionClient struct {
	cc grpc.ClientConnInterface
}

func NewConnectionClient(cc grpc.ClientConnInterface) ConnectionClient {
	return &connectionClient{cc}
}

func (c *connectionClient) Hello(ctx context.Context, in *SecurityToken, opts ...grpc.CallOption) (*SecurityToken, error) {
	out := new(SecurityToken)
	err := c.cc.Invoke(ctx, "/contracts.Connection/Hello", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ConnectionServer is the server API for Connection Service.
// All implementations must embed UnimplementedConnectionServer
// for forward compatibility
type ConnectionServer interface {
	Hello(context.Context, *SecurityToken) (*SecurityToken, error)
	mustEmbedUnimplementedConnectionServer()
}

// UnimplementedConnectionServer must be embedded to have forward compatible implementations.
type UnimplementedConnectionServer struct {
}

func (UnimplementedConnectionServer) Hello(context.Context, *SecurityToken) (*SecurityToken, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Hello not implemented")
}
func (UnimplementedConnectionServer) mustEmbedUnimplementedConnectionServer() {}

// UnsafeConnectionServer may be embedded to opt out of forward compatibility for this Service.
// Use of this interface is not recommended, as added methods to ConnectionServer will
// result in compilation errors.
type UnsafeConnectionServer interface {
	mustEmbedUnimplementedConnectionServer()
}

func RegisterConnectionServer(s grpc.ServiceRegistrar, srv ConnectionServer) {
	s.RegisterService(&Connection_ServiceDesc, srv)
}

func _Connection_Hello_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SecurityToken)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ConnectionServer).Hello(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/contracts.Connection/Hello",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ConnectionServer).Hello(ctx, req.(*SecurityToken))
	}
	return interceptor(ctx, in, info, handler)
}

// Connection_ServiceDesc is the grpc.ServiceDesc for Connection Service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Connection_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "contracts.Connection",
	HandlerType: (*ConnectionServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Hello",
			Handler:    _Connection_Hello_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "agent.proto",
}

// JobsClient is the client API for Jobs Service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type JobsClient interface {
	// StartJob accepts Job with all required params, streams back all queried and found results
	StartJob(ctx context.Context, in *Job, opts ...grpc.CallOption) (Jobs_StartJobClient, error)
	TerminateJob(ctx context.Context, in *JobTermination, opts ...grpc.CallOption) (*None, error)
	RetrieveQueue(ctx context.Context, in *None, opts ...grpc.CallOption) (*Queue, error)
	RetrieveQueueStatus(ctx context.Context, in *None, opts ...grpc.CallOption) (*QueueStatus, error)
}

type jobsClient struct {
	cc grpc.ClientConnInterface
}

func NewJobsClient(cc grpc.ClientConnInterface) JobsClient {
	return &jobsClient{cc}
}

func (c *jobsClient) StartJob(ctx context.Context, in *Job, opts ...grpc.CallOption) (Jobs_StartJobClient, error) {
	stream, err := c.cc.NewStream(ctx, &Jobs_ServiceDesc.Streams[0], "/contracts.Jobs/StartJob", opts...)
	if err != nil {
		return nil, err
	}
	x := &jobsStartJobClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type Jobs_StartJobClient interface {
	Recv() (*HostAuditReport, error)
	grpc.ClientStream
}

type jobsStartJobClient struct {
	grpc.ClientStream
}

func (x *jobsStartJobClient) Recv() (*HostAuditReport, error) {
	m := new(HostAuditReport)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *jobsClient) TerminateJob(ctx context.Context, in *JobTermination, opts ...grpc.CallOption) (*None, error) {
	out := new(None)
	err := c.cc.Invoke(ctx, "/contracts.Jobs/TerminateJob", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *jobsClient) RetrieveQueue(ctx context.Context, in *None, opts ...grpc.CallOption) (*Queue, error) {
	out := new(Queue)
	err := c.cc.Invoke(ctx, "/contracts.Jobs/RetrieveQueue", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *jobsClient) RetrieveQueueStatus(ctx context.Context, in *None, opts ...grpc.CallOption) (*QueueStatus, error) {
	out := new(QueueStatus)
	err := c.cc.Invoke(ctx, "/contracts.Jobs/RetrieveQueueStatus", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// JobsServer is the server API for Jobs Service.
// All implementations must embed UnimplementedJobsServer
// for forward compatibility
type JobsServer interface {
	// StartJob accepts Job with all required params, streams back all queried and found results
	StartJob(*Job, Jobs_StartJobServer) error
	TerminateJob(context.Context, *JobTermination) (*None, error)
	RetrieveQueue(context.Context, *None) (*Queue, error)
	RetrieveQueueStatus(context.Context, *None) (*QueueStatus, error)
	mustEmbedUnimplementedJobsServer()
}

// UnimplementedJobsServer must be embedded to have forward compatible implementations.
type UnimplementedJobsServer struct {
}

func (UnimplementedJobsServer) StartJob(*Job, Jobs_StartJobServer) error {
	return status.Errorf(codes.Unimplemented, "method StartJob not implemented")
}
func (UnimplementedJobsServer) TerminateJob(context.Context, *JobTermination) (*None, error) {
	return nil, status.Errorf(codes.Unimplemented, "method TerminateJob not implemented")
}
func (UnimplementedJobsServer) RetrieveQueue(context.Context, *None) (*Queue, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RetrieveQueue not implemented")
}
func (UnimplementedJobsServer) RetrieveQueueStatus(context.Context, *None) (*QueueStatus, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RetrieveQueueStatus not implemented")
}
func (UnimplementedJobsServer) mustEmbedUnimplementedJobsServer() {}

// UnsafeJobsServer may be embedded to opt out of forward compatibility for this Service.
// Use of this interface is not recommended, as added methods to JobsServer will
// result in compilation errors.
type UnsafeJobsServer interface {
	mustEmbedUnimplementedJobsServer()
}

func RegisterJobsServer(s grpc.ServiceRegistrar, srv JobsServer) {
	s.RegisterService(&Jobs_ServiceDesc, srv)
}

func _Jobs_StartJob_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(Job)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(JobsServer).StartJob(m, &jobsStartJobServer{stream})
}

type Jobs_StartJobServer interface {
	Send(*HostAuditReport) error
	grpc.ServerStream
}

type jobsStartJobServer struct {
	grpc.ServerStream
}

func (x *jobsStartJobServer) Send(m *HostAuditReport) error {
	return x.ServerStream.SendMsg(m)
}

func _Jobs_TerminateJob_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(JobTermination)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(JobsServer).TerminateJob(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/contracts.Jobs/TerminateJob",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(JobsServer).TerminateJob(ctx, req.(*JobTermination))
	}
	return interceptor(ctx, in, info, handler)
}

func _Jobs_RetrieveQueue_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(None)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(JobsServer).RetrieveQueue(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/contracts.Jobs/RetrieveQueue",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(JobsServer).RetrieveQueue(ctx, req.(*None))
	}
	return interceptor(ctx, in, info, handler)
}

func _Jobs_RetrieveQueueStatus_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(None)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(JobsServer).RetrieveQueueStatus(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/contracts.Jobs/RetrieveQueueStatus",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(JobsServer).RetrieveQueueStatus(ctx, req.(*None))
	}
	return interceptor(ctx, in, info, handler)
}

// Jobs_ServiceDesc is the grpc.ServiceDesc for Jobs Service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Jobs_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "contracts.Jobs",
	HandlerType: (*JobsServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "TerminateJob",
			Handler:    _Jobs_TerminateJob_Handler,
		},
		{
			MethodName: "RetrieveQueue",
			Handler:    _Jobs_RetrieveQueue_Handler,
		},
		{
			MethodName: "RetrieveQueueStatus",
			Handler:    _Jobs_RetrieveQueueStatus_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "StartJob",
			Handler:       _Jobs_StartJob_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "agent.proto",
}

// ConfigurationClient is the client API for Configuration Service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ConfigurationClient interface {
	// Reconfigure used to configure agent, returns new config
	Reconfigure(ctx context.Context, in *AgentConfig, opts ...grpc.CallOption) (*AgentConfig, error)
	RetrieveConfig(ctx context.Context, in *None, opts ...grpc.CallOption) (*AgentConfig, error)
}

type configurationClient struct {
	cc grpc.ClientConnInterface
}

func NewConfigurationClient(cc grpc.ClientConnInterface) ConfigurationClient {
	return &configurationClient{cc}
}

func (c *configurationClient) Reconfigure(ctx context.Context, in *AgentConfig, opts ...grpc.CallOption) (*AgentConfig, error) {
	out := new(AgentConfig)
	err := c.cc.Invoke(ctx, "/contracts.Configuration/Reconfigure", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *configurationClient) RetrieveConfig(ctx context.Context, in *None, opts ...grpc.CallOption) (*AgentConfig, error) {
	out := new(AgentConfig)
	err := c.cc.Invoke(ctx, "/contracts.Configuration/RetrieveConfig", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ConfigurationServer is the server API for Configuration Service.
// All implementations must embed UnimplementedConfigurationServer
// for forward compatibility
type ConfigurationServer interface {
	// Reconfigure used to configure agent, returns new config
	Reconfigure(context.Context, *AgentConfig) (*AgentConfig, error)
	RetrieveConfig(context.Context, *None) (*AgentConfig, error)
	mustEmbedUnimplementedConfigurationServer()
}

// UnimplementedConfigurationServer must be embedded to have forward compatible implementations.
type UnimplementedConfigurationServer struct {
}

func (UnimplementedConfigurationServer) Reconfigure(context.Context, *AgentConfig) (*AgentConfig, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Reconfigure not implemented")
}
func (UnimplementedConfigurationServer) RetrieveConfig(context.Context, *None) (*AgentConfig, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RetrieveConfig not implemented")
}
func (UnimplementedConfigurationServer) mustEmbedUnimplementedConfigurationServer() {}

// UnsafeConfigurationServer may be embedded to opt out of forward compatibility for this Service.
// Use of this interface is not recommended, as added methods to ConfigurationServer will
// result in compilation errors.
type UnsafeConfigurationServer interface {
	mustEmbedUnimplementedConfigurationServer()
}

func RegisterConfigurationServer(s grpc.ServiceRegistrar, srv ConfigurationServer) {
	s.RegisterService(&Configuration_ServiceDesc, srv)
}

func _Configuration_Reconfigure_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AgentConfig)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ConfigurationServer).Reconfigure(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/contracts.Configuration/Reconfigure",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ConfigurationServer).Reconfigure(ctx, req.(*AgentConfig))
	}
	return interceptor(ctx, in, info, handler)
}

func _Configuration_RetrieveConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(None)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ConfigurationServer).RetrieveConfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/contracts.Configuration/RetrieveConfig",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ConfigurationServer).RetrieveConfig(ctx, req.(*None))
	}
	return interceptor(ctx, in, info, handler)
}

// Configuration_ServiceDesc is the grpc.ServiceDesc for Configuration Service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Configuration_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "contracts.Configuration",
	HandlerType: (*ConfigurationServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Reconfigure",
			Handler:    _Configuration_Reconfigure_Handler,
		},
		{
			MethodName: "RetrieveConfig",
			Handler:    _Configuration_RetrieveConfig_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "agent.proto",
}
