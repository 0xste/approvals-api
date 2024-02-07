package grpc

import (
	"context"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func RequestTimeout(timeout time.Duration) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp interface{}, err error) {
		nextCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		return handler(nextCtx, req)
	}
}

type notFoundError interface {
	Error() string
	NotFound()
}

func Errors(log *zap.Logger) grpc.UnaryServerInterceptor {
	m := func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Run the next handler and catch any propagated error
		resp, err := handler(ctx, req)
		if err == nil {
			// no error, nothing to do here
			return resp, nil
		}

		// Check if the error is a gRPC one
		if _, ok := status.FromError(err); ok {
			return nil, err
		}

		validationErrs, ok := errors.Cause(err).(validation.Errors)
		if ok {
			st := status.New(codes.InvalidArgument, validationErrs.Error())
			return nil, st.Err()
		}

		notFound, ok := errors.Cause(err).(notFoundError)
		if ok {
			return nil, status.Error(codes.NotFound, notFound.Error())
		}

		log.Error(err.Error())

		return nil, status.Error(codes.Internal, "internal error")
	}

	return m
}

// LogDecider deciding if the gRPC interceptor logs should log.
func LogDecider(_ string, err error) bool {
	code := status.Code(err)
	if code == codes.OK || code == codes.NotFound {
		return false
	}

	return true
}
