package business

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	envoy_auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/openkcm/common-sdk/pkg/commongrpc"
	"github.com/openkcm/extauthz/internal/config"
	"github.com/openkcm/extauthz/internal/extauthz"
)

func startGRPCServer(ctx context.Context, cfg *config.Config, extauthzSrv *extauthz.Server) error {
	// Create a new gRPC server
	grpcServer := commongrpc.NewServer(ctx, &cfg.GRPCServer.GRPCServer)

	// Register the ExtAuthZ server and the health server with the gRPC server
	envoy_auth.RegisterAuthorizationServer(grpcServer, extauthzSrv)

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
