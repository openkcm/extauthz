package business

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/openkcm/common-sdk/pkg/health"
	"github.com/openkcm/extauthz/internal/config"
	"github.com/openkcm/extauthz/internal/extauthz"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
)

// createGRPCServer creates the gRPC server using the given config
func createGRPCServer(_ context.Context, cfg *config.GRPCServer) (*grpc.Server, error) {
	var opts []grpc.ServerOption

	if cfg.MaxRecvMsgSize > 0 {
		opts = append(opts, grpc.MaxRecvMsgSize(cfg.MaxRecvMsgSize))
	}

	enforcementPolicy := keepalive.EnforcementPolicy{
		// If a client pings more than once every 15 sec, terminate the connection
		MinTime: time.Duration(cfg.EfPolMinTime) * time.Second,
		// Allow pings even when there are no active streams
		PermitWithoutStream: cfg.EfPolPermitWithoutStream,
	}
	opts = append(opts, grpc.KeepaliveEnforcementPolicy(enforcementPolicy))

	serverParameters := keepalive.ServerParameters{
		MaxConnectionIdle:     time.Duration(cfg.Attributes.MaxConnectionIdle) * time.Second,
		MaxConnectionAge:      time.Duration(cfg.Attributes.MaxConnectionAge) * time.Second,
		MaxConnectionAgeGrace: time.Duration(cfg.Attributes.MaxConnectionAgeGrace) * time.Second,
		Time:                  time.Duration(cfg.Attributes.Time) * time.Second,
		Timeout:               time.Duration(cfg.Attributes.Timeout) * time.Second,
	}
	opts = append(opts, grpc.KeepaliveParams(serverParameters))

	// create the gRPC server with the given options
	grpcServer := grpc.NewServer(opts...)
	return grpcServer, nil
}

func startGRPCServer(ctx context.Context, cfg *config.Config, extauthzSrv *extauthz.Server) error {
	// Create a new gRPC server
	grpcServer, err := createGRPCServer(ctx, &cfg.GRPCServer)
	if err != nil {
		return fmt.Errorf("failed to create gRPC server: %w", err)
	}

	// Register the ExtAuthZ server and the health server with the gRPC server
	envoy_auth.RegisterAuthorizationServer(grpcServer, extauthzSrv)
	healthpb.RegisterHealthServer(grpcServer, &health.GRPCServer{})

	// Start the gRPC listener and server
	listener, err := net.Listen("tcp", cfg.GRPCServer.Address)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	go func() {
		slog.Info("Starting gRPC Server", "address", cfg.GRPCServer.Address)
		if err = grpcServer.Serve(listener); err != nil {
			slog.Error("Failure on the gRPC server", "error", err)
		}
	}()

	// Shutdown on context cancellation
	<-ctx.Done()
	slog.Info("Stopping gRPC Server", "address", cfg.GRPCServer.Address)
	grpcServer.GracefulStop()
	return nil
}
