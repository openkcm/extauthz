package business

import (
	"context"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/extauthz/internal/config"
)

func Main(ctx context.Context, cfg *config.Config) error {
	slogctx.Info(ctx, "Starting business logic", "name", cfg.Application.Name)

	// create the extauthz server
	extauthzSrv, err := createExtAuthZServer(ctx, cfg)
	if err != nil {
		return err
	}

	return startGRPCServer(ctx, cfg, extauthzSrv)
}
