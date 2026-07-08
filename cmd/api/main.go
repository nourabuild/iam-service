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
		// Because AddSource is true, this will explicitly tell you what line failed
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
	sqlService, err := sqldb.New()
	if err != nil {
		return fmt.Errorf("init database: %w", err)
	}
	defer sqlService.Close()

	// Initialize JWT service
	jwtService := jwt.NewTokenService(cfg.Auth)

	// Initialize Mailtrap service
	emailService := mailtrap.NewMailtrapService(
		cfg.Mailtrap.APIToken,
		cfg.Mailtrap.SenderEmail,
		cfg.Mailtrap.SenderName,
		cfg.Mailtrap.TemplateUUID,
		cfg.Mailtrap.PasswordResetURL,
	)

	// Initialize Kafka producer
	kafkaService := kafka.NewKafkaService()
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
		Handler:      iamApp.RegisterRoutes(cfg.Sentry),
		IdleTimeout:  cfg.HTTP.IdleTimeout,
		ReadTimeout:  cfg.HTTP.ReadTimeout,
		WriteTimeout: cfg.HTTP.WriteTimeout,
		ErrorLog:     slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}

	wg.Go(func() {
		logger.Info("server starting", "addr", srv.Addr, "build", build)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("listen and serve", "error", err)
			stop() // Cancel context if server crashes
		}
	})

	// Relay outbox events to Kafka (at-least-once delivery).
	wg.Go(func() {
		iamApp.RunOutboxRelay(ctx, outboxRelayInterval)
	})

	// Periodically purge expired tokens and delivered outbox events.
	wg.Go(func() {
		cleanup := func() {
			cctx, cancel := context.WithTimeout(context.Background(), time.Minute)
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

	// Graceful Shutdown Wait
	<-ctx.Done()
	logger.Info("shutting down gracefully")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}

	wg.Wait()
	logger.Info("shutdown complete")
	return nil
}
