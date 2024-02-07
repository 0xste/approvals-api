package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/0xste/approvals-api/cmd/approvals/config"
	proto "github.com/0xste/approvals-api/proto/gen"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	grpc_zap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/pflag"
	"google.golang.org/grpc/status"

	apiGrpc "github.com/0xste/approvals-api/cmd/approvals/grpc"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

func main() {
	dev := pflag.Bool("dev", true, "Development mode")
	envFile := pflag.String("env-file", "", "Load environment variables from file")
	pflag.Parse()
	err := viper.BindPFlags(pflag.CommandLine)
	if err != nil {
		log.Fatal(err)
	}

	//get config
	cfg, err := config.GetConfig(*dev, *envFile)
	if err != nil {
		log.Fatal(fmt.Sprintf("error on getting config: %s", err))
	}

	logger, err := zap.NewDevelopment()
	if err != nil {
		log.Fatal(err)
	}

	if err = run(logger, cfg); err != nil {
		logger.Fatal(err.Error())
	}
}

func run(logger *zap.Logger, cfg *config.Config) error {
	grpcUnaryChain := grpc.ChainUnaryInterceptor(grpc_middleware.ChainUnaryServer(
		grpc_zap.UnaryServerInterceptor(
			zap.NewNop(), // todo uplift bdlogger lib to unwrap access to underlying zap logger here
			grpc_zap.WithDecider(apiGrpc.LogDecider),
		),
		grpc_auth.UnaryServerInterceptor(func(ctx context.Context) (context.Context, error) {
			return ctx, nil
		}), // a customizable (via AuthFunc) piece of auth middleware. Does nothing for now
		grpc_recovery.UnaryServerInterceptor(),
		apiGrpc.RequestTimeout(cfg.Server.RequestTimeout),
		apiGrpc.Errors(logger),
	))

	registry := prometheus.NewRegistry()
	apiServer, err := apiGrpc.New(
		apiGrpc.WithLogger(logger),
		apiGrpc.WithMetricsRegistry(registry),
	)
	if err != nil {
		return fmt.Errorf("failed to create api server %s", err.Error())
	}

	grpcMetrics := grpc_prometheus.NewServerMetrics() // server metrics
	registry.MustRegister(grpcMetrics)

	grpcServer := grpc.NewServer(grpcUnaryChain,
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionAge: time.Minute * 5,
		}),
		grpc.StreamInterceptor(grpcMetrics.StreamServerInterceptor()),
		grpc.UnaryInterceptor(grpcMetrics.UnaryServerInterceptor()),
	)
	grpcMetrics.InitializeMetrics(grpcServer)

	proto.RegisterApprovalServiceServer(grpcServer, apiServer)

	grpcListener, err := net.Listen("tcp", cfg.Server.GRPCPort)
	if err != nil {
		return err
	}

	var group errgroup.Group
	group.Go(func() error {
		logger.Info("starting grpc server on port: " + cfg.Server.GRPCPort)
		return grpcServer.Serve(grpcListener)
	})
	group.Go(func() error {
		mux := runtime.NewServeMux(
			runtime.WithErrorHandler(CustomHTTPError),
		)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		opts := []grpc.DialOption{
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		}

		if err := proto.RegisterApprovalServiceHandlerFromEndpoint(ctx, mux, cfg.Server.GRPCPort, opts); err != nil {
			return err
		}

		httpListener, err := net.Listen("tcp", cfg.Server.HTTPPort)
		if err != nil {
			return err
		}

		logger.Info("Starting http gateway server on port: " + cfg.Server.HTTPPort)
		return http.Serve(httpListener, mux)
	})
	group.Go(func() error {
		httpServer := &http.Server{Handler: promhttp.HandlerFor(registry, promhttp.HandlerOpts{}), Addr: cfg.Server.PromPort}
		logger.Info("starting prometheus metric server on port: " + cfg.Server.PromPort)
		return httpServer.ListenAndServe()
	})

	return group.Wait()
}

type newError struct {
	Error errorBody `json:"error,omitempty"`
}

type errorBody struct {
	Message string `json:"message,omitempty"`
}

func CustomHTTPError(_ context.Context, _ *runtime.ServeMux, _ runtime.Marshaler, w http.ResponseWriter, _ *http.Request, err error) {
	const fallback = `{"error": {"message":"failed to marshal error message"}}`
	w.Header().Set("Content-type", "application/json")
	w.WriteHeader(runtime.HTTPStatusFromCode(status.Code(err)))
	jErr := json.NewEncoder(w).Encode(newError{
		Error: errorBody{
			Message: status.Convert(err).Message(),
		},
	})
	if jErr != nil {
		_, _ = w.Write([]byte(fallback))
	}
}
