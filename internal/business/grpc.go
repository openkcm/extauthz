package business

import (
	"context"
	"fmt"
	"net"

	"github.com/openkcm/common-sdk/pkg/commongrpc"
	"github.com/samber/oops"

	envoyauth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/extauthz/internal/config"
	"github.com/openkcm/extauthz/internal/extauthz"
)

func startGRPCServer(ctx context.Context, cfg *config.Config, extauthzSrv *extauthz.Server) error {
	// Start internal processes of the server
	err := extauthzSrv.Start()
	if err != nil {
		return oops.Hint("failed to start internal processes of server").Wrap(err)
	}

	defer func() {
		// Stop internal processes of the server
		err := extauthzSrv.Close()
		if err != nil {
			slogctx.Error(ctx, "failed to stop internal processes of server", "error", err)
		}
	}()

	// Create a new gRPC server
	grpcServer := commongrpc.NewServer(ctx, &cfg.GRPCServer.GRPCServer)

	// Register the ExtAuthZ server and the health server with the gRPC server
	envoyauth.RegisterAuthorizationServer(grpcServer, extauthzSrv)

	// Start the gRPC listener and server
	var lc net.ListenConfig

	listener, err := lc.Listen(ctx, "tcp", cfg.GRPCServer.Address)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	go func() {
		slogctx.Info(ctx, "Starting gRPC Server", "address", cfg.GRPCServer.Address)

		err = grpcServer.Serve(listener)
		if err != nil {
			slogctx.Error(ctx, "Failure on the gRPC server", "error", err)
		}
	}()

	// Shutdown on context cancellation
	<-ctx.Done()
	slogctx.Info(ctx, "Stopping gRPC Server", "address", cfg.GRPCServer.Address)
	grpcServer.GracefulStop()

	return nil
}
