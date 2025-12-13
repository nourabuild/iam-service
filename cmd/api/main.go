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

	// 1. Initialize Database
	dbService := sqldb.New()

	// 2. Initialize Services
	hashService := hash.NewHashService()
	jwtService := jwt.NewTokenService()
	mailtrapService := mailtrap.NewMailtrapService()
	sentryService := sentry.NewSentryService()

	// 3. Initialize App
	app := app.NewApp(dbService, hashService, jwtService, mailtrapService, sentryService)

	// 4. Configure Server
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

	// 5. Graceful Shutdown Logic
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

	// 6. Start Server
	logger.Info("Starting server", "port", srv.Addr)
	err := srv.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("http server error: %w", err)
	}

	<-done
	logger.Info("Graceful shutdown complete")
	return nil
}
