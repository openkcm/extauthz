package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/openkcm/common-sdk/pkg/commoncfg"
	"github.com/openkcm/common-sdk/pkg/health"
	"github.com/openkcm/common-sdk/pkg/logger"
	"github.com/openkcm/common-sdk/pkg/otlp"
	"github.com/openkcm/common-sdk/pkg/status"
	"github.com/samber/oops"

	slogctx "github.com/veqryn/slog-context"

	root "github.com/openkcm/extauthz"
	"github.com/openkcm/extauthz/internal/business"
	"github.com/openkcm/extauthz/internal/config"
)

var versionFlag = flag.Bool("version", false, "print version information")
var gracefulShutdownSec = flag.Int64("graceful-shutdown", 1, "graceful shutdown seconds")
var gracefulShutdownMessage = flag.String("graceful-shutdown-message", "Graceful shutdown in %d seconds",
	"graceful shutdown message")

// run does the heavy lifting until the service is up and running. It will:
//   - Load the config and initializes the logger
//   - Start the status server in a goroutine
//   - Start the business logic and eventually return the error from it
func run(ctx context.Context) error {
	// Load Configuration
	defaults := map[string]any{}
	cfg := &config.Config{}

	err := commoncfg.LoadConfig(cfg,
		defaults,
		"/etc/extauthz",
		"$HOME/.extauthz",
		".",
	)
	if err != nil {
		return oops.In("main").
			Wrapf(err, "Failed to load the configuration")
	}

	err = commoncfg.UpdateConfigVersion(&cfg.BaseConfig, root.BuildVersion)
	if err != nil {
		return oops.In("main").
			Wrapf(err, "Failed to update the version configuration")
	}

	// Logger initialisation
	err = logger.InitAsDefault(cfg.Logger, cfg.Application)
	if err != nil {
		return oops.In("main").
			Wrapf(err, "Failed to initialise the logger")
	}

	// OpenTelemetry initialisation
	err = otlp.Init(ctx, &cfg.Application, &cfg.Telemetry, &cfg.Logger)
	if err != nil {
		return oops.In("main").
			Wrapf(err, "Failed to load the telemetry")
	}

	// Status Server Initialisation
	go func() {
		liveness := status.WithLiveness(
			health.NewHandler(
				health.NewChecker(health.WithDisabledAutostart()),
			),
		)

		healthOptions := make([]health.Option, 0)
		healthOptions = append(healthOptions,
			health.WithDisabledAutostart(),
			health.WithTimeout(5*time.Second),
			health.WithStatusListener(func(ctx context.Context, state health.State) {
				slogctx.Info(ctx, "readiness status changed", "status", state.Status)
			}),
		)

		cfg.GRPCServer.Client.Address = cfg.GRPCServer.Address
		healthOptions = append(healthOptions,
			health.WithGRPCServerChecker(cfg.GRPCServer.Client),
		)

		readiness := status.WithReadiness(
			health.NewHandler(
				health.NewChecker(healthOptions...),
			),
		)

		err := status.Start(ctx, &cfg.BaseConfig, liveness, readiness)
		if err != nil {
			slogctx.Error(ctx, "Failure on the status server", "error", err)

			_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
		}
	}()

	// Business Logic
	err = business.Main(ctx, cfg)
	if err != nil {
		return oops.In("main").
			Wrapf(err, "Failed to start the main business application")
	}

	return nil
}

// runFuncWithSignalHandling runs the given function with signal handling. When
// a CTRL-C is received, the context will be cancelled on which the function can
// act upon.
func runFuncWithSignalHandling(f func(context.Context) error) int {
	ctx, cancelOnSignal := signal.NotifyContext(
		context.Background(),
		os.Interrupt, syscall.SIGTERM,
	)
	defer cancelOnSignal()

	exitCode := 0

	err := f(ctx)
	if err != nil {
		slogctx.Error(ctx, "Failed to start the application", "error", err)
		_, _ = fmt.Fprintln(os.Stderr, err)
		exitCode = 1
	}

	// graceful shutdown so running goroutines may finish
	_, _ = fmt.Fprintln(os.Stderr, fmt.Sprintf(*gracefulShutdownMessage, *gracefulShutdownSec))
	time.Sleep(time.Duration(*gracefulShutdownSec) * time.Second)

	return exitCode
}

// main is the entry point for the application. It is intentionally kept small
// because it is hard to test, which would lower test coverage.
func main() {
	flag.Parse()

	if *versionFlag {
		fmt.Println(root.BuildVersion)
		os.Exit(0)
	}

	exitCode := runFuncWithSignalHandling(run)
	os.Exit(exitCode)
}
