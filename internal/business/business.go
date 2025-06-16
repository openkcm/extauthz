package business

import (
	"context"
	"log/slog"

	"github.com/openkcm/extauthz/internal/config"
)

func Main(ctx context.Context, cfg *config.Config) error {
	slog.Info("Starting business logic", "name", cfg.Application.Name)

	// create the extauthz server
	extauthzSrv, err := createExtAuthZServer(ctx, cfg)
	if err != nil {
		return err
	}

	return startGRPCServer(ctx, cfg, extauthzSrv)
}
