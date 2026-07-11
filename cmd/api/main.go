package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	_ "github.com/joho/godotenv/autoload"
	"github.com/nourabuild/iam-service/internal/app"
	"github.com/nourabuild/iam-service/internal/sdk/config"
	"github.com/nourabuild/iam-service/internal/sdk/observability"
	"github.com/nourabuild/iam-service/internal/sdk/sqldb"
	"github.com/nourabuild/iam-service/internal/services/jwt"
	"github.com/nourabuild/iam-service/internal/services/kafka"
	"github.com/nourabuild/iam-service/internal/services/mailtrap"
	"github.com/nourabuild/iam-service/internal/services/sentry"
)

var build string

const (
	// tokenCleanupInterval is how often expired refresh and password-reset
	// tokens are purged. Without this, both tables grow unboundedly.
	tokenCleanupInterval = 6 * time.Hour

	// outboxRelayInterval is how often pending events are drained to Kafka.
	outboxRelayInterval = 2 * time.Second

	// outboxRetention is how long delivered events are kept for debugging
	// before the cleanup job removes them.
	outboxRetention = 7 * 24 * time.Hour
)

func main() {
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

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	shutdownSentry, err := sentry.SetupSentry(ctx, cfg.Sentry, logger)
	if err != nil {
		return fmt.Errorf("setup sentry: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Sentry.SentryFlushTimeout)
		defer cancel()
		if err := shutdownSentry(shutdownCtx); err != nil {
			logger.Error("shutdown sentry", "error", err)
		}
	}()

	shutdownTracing, err := observability.SetupTracing(ctx, cfg.Observability, logger)
	if err != nil {
		return fmt.Errorf("setup tracing: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdownTracing(shutdownCtx); err != nil {
			logger.Error("shutdown tracing", "error", err)
		}
	}()

	var wg sync.WaitGroup

	// Initialize Database service
	sqlService, err := sqldb.New(cfg.DB)
	if err != nil {
		return fmt.Errorf("init database: %w", err)
	}
	defer func() {
		if err := sqlService.Close(); err != nil {
			logger.Error("close database", "error", err)
		}
	}()

	// Initialize JWT service
	jwtService := jwt.NewTokenService(cfg.Auth)

	// Initialize Mailtrap service
	emailService := mailtrap.NewMailtrapService(cfg.Mailtrap)

	// Initialize Kafka producer
	kafkaService := kafka.NewKafkaService(ctx)
	if kafkaService != nil {
		defer kafkaService.Close()
	}

	// App Initialization
	iamApp := app.NewApp(
		sqlService,
		jwtService,
		emailService,
		kafkaService,
	)

	// HTTP server with configured timeouts
	srv := &http.Server{
		Addr:         ":" + cfg.HTTP.Port,
		Handler:      iamApp.RegisterRoutes(cfg),
		IdleTimeout:  cfg.HTTP.IdleTimeout,
		ReadTimeout:  cfg.HTTP.ReadTimeout,
		WriteTimeout: cfg.HTTP.WriteTimeout,
		ErrorLog:     slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}

	serveErrors := make(chan error, 1)
	wg.Go(func() {
		logger.Info("server starting", "addr", srv.Addr, "build", build)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErrors <- err
		}
	})

	// Relay outbox events to Kafka (at-least-once delivery).
	wg.Go(func() {
		iamApp.RunOutboxRelay(ctx, outboxRelayInterval)
	})

	// Periodically purge expired tokens and delivered outbox events.
	wg.Go(func() {
		cleanup := func() {
			cctx, cancel := context.WithTimeout(ctx, time.Minute)
			defer cancel()
			if err := sqlService.DeleteExpiredRefreshTokens(cctx); err != nil {
				logger.Error("cleanup expired refresh tokens", "error", err)
			}
			if err := sqlService.DeleteExpiredPasswordResetTokens(cctx); err != nil {
				logger.Error("cleanup expired password reset tokens", "error", err)
			}
			if err := sqlService.DeletePublishedOutbox(cctx, outboxRetention); err != nil {
				logger.Error("cleanup published outbox events", "error", err)
			}
		}

		cleanup()
		ticker := time.NewTicker(tokenCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cleanup()
			}
		}
	})

	// Wait for a shutdown signal or an unexpected listener failure. Preserve
	// the listener error so startup failures result in a non-zero process exit.
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-serveErrors:
		stop()
	}
	logger.Info("shutting down gracefully")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	shutdownErr := srv.Shutdown(shutdownCtx)
	if shutdownErr != nil {
		logger.Error("graceful HTTP shutdown failed", "error", shutdownErr)
		if err := srv.Close(); err != nil {
			logger.Error("force close HTTP server", "error", err)
		}
	}

	wg.Wait()
	if shutdownErr != nil {
		return fmt.Errorf("shutdown HTTP server: %w", shutdownErr)
	}
	if serveErr != nil {
		return fmt.Errorf("listen and serve: %w", serveErr)
	}
	logger.Info("shutdown complete")
	return nil
}
