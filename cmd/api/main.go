package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
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

func main() {
	if err := run(); err != nil {
		log.Fatalf("Application failed: %v", err)
	}
}

func run() error {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	logger.Info("GOMAXPROCS", "cpu", runtime.GOMAXPROCS(0))

	// 1. Initialize Tracing
	traceConfig := otel.Config{
		ServiceName: "iam-service",
		Host:        os.Getenv("OTEL_EXPORTER_HOST"),
		Probability: 1.0,
	}
	traceProvider, teardown, err := otel.InitTracing(traceConfig)
	if err != nil {
		return fmt.Errorf("initializing tracing: %w", err)
	}
	defer teardown(context.Background())

	tracer := traceProvider.Tracer("iam-service")

	// 2. Initialize Database
	dbService := sqldb.New()

	// 3. Initialize Services
	hashService := hash.NewHashService()
	jwtService := jwt.NewTokenService()
	mailtrapService := mailtrap.NewMailtrapService()
	sentryService := sentry.NewSentryService()

	// 4. Initialize App
	app := app.NewApp(dbService, hashService, jwtService, mailtrapService, sentryService, tracer)

	// 5. Configure Server
	port, _ := strconv.Atoi(os.Getenv("PORT"))
	if port == 0 {
		port = 8080 // Fallback default
	}

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      app.RegisterRoutes(),
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// 6. Graceful Shutdown Logic
	done := make(chan bool, 1)
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		logger.Info("shutting down gracefully, press Ctrl+C again to force")

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			logger.Error("Server forced to shutdown", "error", err)
		}
		done <- true
	}()

	// 7. Start Server
	logger.Info("Starting server", "port", srv.Addr)
	err = srv.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("http server error: %w", err)
	}

	<-done
	logger.Info("Graceful shutdown complete")
	return nil
}
