package grpc

import (
	"context"

	proto "github.com/0xste/approvals-api/proto/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) GetUser(ctx context.Context, request *proto.GetUserRequest) (*proto.GetUserResponse, error) {
	start, stat := s.entryMetrics()
	defer s.exitMetrics(start, stat)
	return nil, unimplemented()
}

func (s *Server) CreateUser(ctx context.Context, request *proto.CreateUserRequest) (*proto.CreateUserResponse, error) {
	start, stat := s.entryMetrics()
	defer s.exitMetrics(start, stat)
	return nil, unimplemented()
}

func (s *Server) GetRoles(ctx context.Context, request *proto.GetRoleRequest) (*proto.GetRoleResponse, error) {
	start, stat := s.entryMetrics()
	defer s.exitMetrics(start, stat)
	return nil, unimplemented()
}

func (s *Server) CreateRole(ctx context.Context, request *proto.CreateRoleRequest) (*proto.CreateRoleResponse, error) {
	start, stat := s.entryMetrics()
	defer s.exitMetrics(start, stat)
	return nil, unimplemented()
}

func (s *Server) GetRoleAssignments(ctx context.Context, request *proto.GetRoleAssignmentRequest) (*proto.GetRoleAssignmentResponse, error) {
	start, stat := s.entryMetrics()
	defer s.exitMetrics(start, stat)
	return nil, unimplemented()
}

func (s *Server) CreateRoleAssignment(ctx context.Context, request *proto.CreateRoleAssignmentRequest) (*proto.CreateRoleAssignmentResponse, error) {
	start, stat := s.entryMetrics()
	defer s.exitMetrics(start, stat)
	return nil, unimplemented()
}

func (s *Server) GetFunctions(ctx context.Context, request *proto.GetFunctionRequest) (*proto.GetFunctionResponse, error) {
	start, stat := s.entryMetrics()
	defer s.exitMetrics(start, stat)
	return nil, unimplemented()
}

func (s *Server) CreateFunction(ctx context.Context, request *proto.CreateFunctionRequest) (*proto.CreateFunctionResponse, error) {
	start, stat := s.entryMetrics()
	defer s.exitMetrics(start, stat)
	return nil, unimplemented()
}

func (s *Server) CreateApproval(ctx context.Context, request *proto.CreateApprovalRequest) (*proto.CreateApprovalResponse, error) {
	start, stat := s.entryMetrics()
	defer s.exitMetrics(start, stat)
	return nil, unimplemented()
}

func (s *Server) ApproveApproval(ctx context.Context, request *proto.ApproveApprovalRequest) (*proto.ApproveApprovalResponse, error) {
	start, stat := s.entryMetrics()
	defer s.exitMetrics(start, stat)
	return nil, unimplemented()
}

func unimplemented() error {
	return status.Errorf(codes.Unimplemented, "method %s not implemented", currentFunction())
}
