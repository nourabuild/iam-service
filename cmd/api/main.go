package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync" // Now includes the .Go() method
	"syscall"
	"time"

	_ "github.com/joho/godotenv/autoload"
	"github.com/nourabuild/iam-service/internal/app"
	"github.com/nourabuild/iam-service/internal/sdk/otel"
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
	"github.com/nourabuild/iam-service/internal/services/hash"
	"github.com/nourabuild/iam-service/internal/services/jwt"
	"github.com/nourabuild/iam-service/internal/services/mailtrap"
	"github.com/nourabuild/iam-service/internal/services/sentry"
)

var build string

func main() {
	// 1. Optimized Logging: Defaulting to JSON for production
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("application startup failed", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 2. Resource Management with WaitGroups
	var wg sync.WaitGroup

	// 3. Tracing with Flight Recorder
	traceConfig := otel.Config{
		ServiceName: "iam-service",
		Host:        os.Getenv("OTEL_EXPORTER_HOST"),
		Probability: 1.0,
	}
	traceProvider, teardown, err := otel.InitTracing(traceConfig)
	if err != nil {
		return fmt.Errorf("otel: %w", err)
	}
	defer teardown(context.Background())

	// 4. App Initialization
	app := app.NewApp(
		sqldb.New(),
		traceProvider.Tracer("iam-service"),
		hash.NewHashService(),
		jwt.NewTokenService(),
		mailtrap.NewMailtrapService(),
		sentry.NewSentryService(),
	)

	// 5. Modern Server with CSRF Protection
	srv := &http.Server{
		Addr:         ":" + getEnv("PORT", "8080"),
		Handler:      app.RegisterRoutes(),
		IdleTimeout:  time.Minute,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		ErrorLog:     slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}

	wg.Go(func() {
		logger.Info("server starting", "addr", srv.Addr, "build", build)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("listen and serve", "error", err)
			stop() // Cancel context if server crashes
		}
	})

	// 7. Graceful Shutdown Wait
	<-ctx.Done()
	logger.Info("shutting down gracefully")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}

	logger.Info("shutdown complete")
	return nil
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}
