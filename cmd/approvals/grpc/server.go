package grpc

import (
	"context"
	"fmt"

	proto "github.com/0xste/approvals-api/proto/gen"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Server holds all dependencies for the grpc server
type Server struct {
	// must be embedded to have forward compatible implementations.
	proto.UnimplementedApprovalServiceServer
	log     *zap.Logger
	metrics *Metrics
}

var _ proto.ApprovalServiceServer = (*Server)(nil)

type ErrInvalidServer struct {
	Field string
}

func (e *ErrInvalidServer) Error() string {
	return fmt.Sprintf("invalid server config: %s", e.Field)
}

// New is the constructor
func New(options ...func(c *Server)) (*Server, error) {
	client := &Server{}
	for _, option := range options {
		option(client)
	}
	if client.log == nil {
		client.log = zap.NewNop()
	}
	if client.metrics == nil {
		client.metrics = NewMetrics(prometheus.DefaultRegisterer)
	}
	return client, nil
}

// WithLogger references the logger
func WithLogger(logger *zap.Logger) func(*Server) {
	return func(c *Server) {
		c.log = logger
	}
}

// WithMetricsRegistry references the prometheus metrics
func WithMetricsRegistry(reg *prometheus.Registry) func(*Server) {
	return func(c *Server) {
		c.metrics = NewMetrics(reg)
	}
}

// GetStatus returns an empty response for the purpose of a probe
func (s *Server) GetStatus(context.Context, *emptypb.Empty) (*emptypb.Empty, error) {
	return &emptypb.Empty{}, nil
}
