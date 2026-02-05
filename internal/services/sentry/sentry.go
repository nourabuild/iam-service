// Package sentry provides error tracking and monitoring using Sentry.
package sentry

import (
	"os"
	"time"

	"github.com/getsentry/sentry-go"
)

const (
	LevelDebug   Level = sentry.LevelDebug
	LevelInfo    Level = sentry.LevelInfo
	LevelWarning Level = sentry.LevelWarning
	LevelError   Level = sentry.LevelError
	LevelFatal   Level = sentry.LevelFatal
)

type Scope = sentry.Scope
type Level = sentry.Level

type SentryRepository interface {
	CaptureException(err error)
	CaptureMessage(message string)
	Flush(timeout time.Duration) bool
	Close()
	Recover()
	WithScope(fn func(scope *Scope))
}

type SentryService struct {
	Dsn         string
	Environment string
	Debug       bool
	SampleRate  float64
}

// NewSentryService initializes Sentry and returns the service
func NewSentryService() *SentryService {
	env := os.Getenv("SENTRY_ENVIRONMENT")
	if env == "" {
		env = "development"
	}

	dsn := os.Getenv("SENTRY_DSN")
	debug := env == "development"
	sampleRate := 1.0

	_ = sentry.Init(sentry.ClientOptions{
		Dsn:         dsn,
		Environment: env,
		Debug:       debug,
		SampleRate:  sampleRate,
	})

	return &SentryService{
		Dsn:         dsn,
		Environment: env,
		Debug:       debug,
		SampleRate:  sampleRate,
	}
}

// CaptureException sends an error to Sentry.
func (s *SentryService) CaptureException(err error) {
	if err == nil {
		return
	}
	sentry.CaptureException(err)
}

// CaptureMessage sends a message to Sentry.
func (s *SentryService) CaptureMessage(message string) {
	sentry.CaptureMessage(message)
}

// Flush waits for all events to be sent to Sentry.
func (s *SentryService) Flush(timeout time.Duration) bool {
	return sentry.Flush(timeout)
}

// Close flushes pending events and shuts down the Sentry client
func (s *SentryService) Close() {
	s.Flush(2 * time.Second)
}

// Recover captures a panic and sends it to Sentry
func (s *SentryService) Recover() {
	if r := recover(); r != nil {
		sentry.CurrentHub().Recover(r)
		sentry.Flush(2 * time.Second)
	}
}

// WithScope allows you to modify the Sentry scope for a specific operation
func (s *SentryService) WithScope(fn func(scope *Scope)) {
	sentry.WithScope(fn)
}

// ============================================================================

// // Package sentry provides error tracking and monitoring using Sentry.
// package sentry

// import (
// 	"context"
// 	"fmt"
// 	"os"
// 	"runtime/debug"
// 	"time"

// 	"github.com/getsentry/sentry-go"
// )

// // Level aliases for convenience
// const (
// 	LevelDebug   Level = sentry.LevelDebug
// 	LevelInfo    Level = sentry.LevelInfo
// 	LevelWarning Level = sentry.LevelWarning
// 	LevelError   Level = sentry.LevelError
// 	LevelFatal   Level = sentry.LevelFatal
// )

// type (
// 	// Scope and Level are aliases for sentry types
// 	Scope = sentry.Scope
// 	Level = sentry.Level
// )

// // Repository defines the interface for Sentry operations
// type Repository interface {
// 	CaptureException(ctx context.Context, err error)
// 	CaptureMessage(ctx context.Context, message string, level Level)
// 	CaptureEvent(ctx context.Context, event *sentry.Event)
// 	Flush(timeout time.Duration) bool
// 	Close() error
// 	Recover(ctx context.Context)
// 	WithScope(fn func(scope *Scope))
// 	AddBreadcrumb(ctx context.Context, breadcrumb *sentry.Breadcrumb)
// 	SetUser(ctx context.Context, user sentry.User)
// 	SetTag(ctx context.Context, key, value string)
// 	SetContext(ctx context.Context, name string, data map[string]interface{})
// }

// // Config holds Sentry configuration options
// type Config struct {
// 	DSN              string
// 	Environment      string
// 	Debug            bool
// 	SampleRate       float64
// 	AttachStacktrace bool
// 	Release          string
// 	ServerName       string
// 	Dist             string
// 	EnableTracing    bool
// 	TracesSampleRate float64
// 	BeforeSend       func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event
// }

// // Service implements the Repository interface
// type Service struct {
// 	hub    *sentry.Hub
// 	client *sentry.Client
// 	config Config
// 	closed bool
// }

// // New creates a new Sentry service with the provided configuration.
// // Returns an error if initialization fails.
// func New(cfg Config) (*Service, error) {
// 	if cfg.DSN == "" {
// 		return nil, fmt.Errorf("sentry DSN is required")
// 	}

// 	if cfg.Environment == "" {
// 		cfg.Environment = getEnv("SENTRY_ENVIRONMENT", "development")
// 	}
// 	if cfg.Release == "" {
// 		cfg.Release = getEnv("SENTRY_RELEASE", "")
// 	}
// 	if cfg.ServerName == "" {
// 		cfg.ServerName = getEnv("SENTRY_SERVER_NAME", "")
// 	}
// 	if cfg.SampleRate == 0 {
// 		cfg.SampleRate = 1.0
// 	}

// 	client, err := sentry.NewClient(sentry.ClientOptions{
// 		Dsn:              cfg.DSN,
// 		Environment:      cfg.Environment,
// 		Debug:            cfg.Debug,
// 		SampleRate:       cfg.SampleRate,
// 		AttachStacktrace: cfg.AttachStacktrace,
// 		Release:          cfg.Release,
// 		ServerName:       cfg.ServerName,
// 		Dist:             cfg.Dist,
// 		EnableTracing:    cfg.EnableTracing,
// 		TracesSampleRate: cfg.TracesSampleRate,
// 		BeforeSend:       cfg.BeforeSend,
// 	})
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to initialize sentry client: %w", err)
// 	}

// 	hub := sentry.NewHub(client, sentry.NewScope())

// 	return &Service{
// 		hub:    hub,
// 		client: client,
// 		config: cfg,
// 	}, nil
// }

// // NewFromEnv creates a new Sentry service using environment variables.
// func NewFromEnv() (*Service, error) {
// 	cfg := Config{
// 		DSN:              os.Getenv("SENTRY_DSN"),
// 		Environment:      os.Getenv("SENTRY_ENVIRONMENT"),
// 		Release:          os.Getenv("SENTRY_RELEASE"),
// 		ServerName:       os.Getenv("SENTRY_SERVER_NAME"),
// 		Debug:            os.Getenv("SENTRY_DEBUG") == "true",
// 		AttachStacktrace: true,
// 	}

// 	if rate := os.Getenv("SENTRY_SAMPLE_RATE"); rate != "" {
// 		if _, err := fmt.Sscanf(rate, "%f", &cfg.SampleRate); err != nil {
// 			cfg.SampleRate = 1.0
// 		}
// 	}

// 	return New(cfg)
// }

// // CaptureException sends an error to Sentry with optional context enrichment.
// func (s *Service) CaptureException(ctx context.Context, err error) {
// 	if err == nil || s.closed {
// 		return
// 	}

// 	s.withContextScope(ctx, func(scope *Scope) {
// 		s.hub.CaptureException(err)
// 	})
// }

// // CaptureMessage sends a message to Sentry with specified level.
// func (s *Service) CaptureMessage(ctx context.Context, message string, level Level) {
// 	if message == "" || s.closed {
// 		return
// 	}

// 	s.withContextScope(ctx, func(scope *Scope) {
// 		scope.SetLevel(level)
// 		s.hub.CaptureMessage(message)
// 	})
// }

// // CaptureEvent sends a custom event to Sentry.
// func (s *Service) CaptureEvent(ctx context.Context, event *sentry.Event) {
// 	if event == nil || s.closed {
// 		return
// 	}

// 	s.withContextScope(ctx, func(scope *Scope) {
// 		s.hub.CaptureEvent(event)
// 	})
// }

// // AddBreadcrumb adds a breadcrumb to the current scope.
// func (s *Service) AddBreadcrumb(ctx context.Context, breadcrumb *sentry.Breadcrumb) {
// 	if breadcrumb == nil {
// 		return
// 	}
// 	s.hub.AddBreadcrumb(breadcrumb, nil)
// }

// // SetUser sets user information in the current scope.
// func (s *Service) SetUser(ctx context.Context, user sentry.User) {
// 	s.hub.Scope().SetUser(user)
// }

// // SetTag sets a tag in the current scope.
// func (s *Service) SetTag(ctx context.Context, key, value string) {
// 	s.hub.Scope().SetTag(key, value)
// }

// // SetContext sets additional context data in the current scope.
// func (s *Service) SetContext(ctx context.Context, name string, data map[string]interface{}) {
// 	s.hub.Scope().SetContext(name, data)
// }

// // Flush waits for all events to be sent to Sentry within the timeout.
// func (s *Service) Flush(timeout time.Duration) bool {
// 	if s.closed {
// 		return true
// 	}
// 	return s.client.Flush(timeout)
// }

// // Close flushes pending events and shuts down the Sentry client.
// func (s *Service) Close() error {
// 	if s.closed {
// 		return nil
// 	}

// 	s.closed = true
// 	if !s.Flush(5 * time.Second) {
// 		return fmt.Errorf("failed to flush all events within timeout")
// 	}
// 	s.client.Close()
// 	return nil
// }

// // Recover captures a panic, sends it to Sentry, and re-panics.
// // Usage: defer service.Recover(ctx)
// func (s *Service) Recover(ctx context.Context) {
// 	if r := recover(); r != nil {
// 		s.hub.WithScope(func(scope *Scope) {
// 			scope.SetLevel(sentry.LevelFatal)
// 			scope.SetExtra("stacktrace", string(debug.Stack()))
// 			s.withContextScope(ctx, func(*Scope) {
// 				s.hub.Recover(r)
// 			})
// 		})
// 		s.Flush(5 * time.Second)
// 		panic(r) // Re-panic after capturing
// 	}
// }

// // RecoverAndContinue captures a panic and continues execution without re-panicking.
// // Usage: defer service.RecoverAndContinue(ctx)
// func (s *Service) RecoverAndContinue(ctx context.Context) {
// 	if r := recover(); r != nil {
// 		s.hub.WithScope(func(scope *Scope) {
// 			scope.SetLevel(sentry.LevelFatal)
// 			scope.SetExtra("stacktrace", string(debug.Stack()))
// 			s.withContextScope(ctx, func(*Scope) {
// 				s.hub.Recover(r)
// 			})
// 		})
// 		s.Flush(5 * time.Second)
// 	}
// }

// // WithScope executes a function with a temporary scope.
// func (s *Service) WithScope(fn func(scope *Scope)) {
// 	s.hub.WithScope(fn)
// }

// // Clone returns a new service with a cloned hub for concurrent use.
// func (s *Service) Clone() *Service {
// 	return &Service{
// 		hub:    s.hub.Clone(),
// 		client: s.client,
// 		config: s.config,
// 		closed: s.closed,
// 	}
// }

// // withContextScope enriches scope with context data if available.
// func (s *Service) withContextScope(ctx context.Context, fn func(*Scope)) {
// 	if ctx == nil {
// 		fn(s.hub.Scope())
// 		return
// 	}

// 	s.hub.WithScope(func(scope *Scope) {
// 		// Extract and set trace/span info if using Sentry tracing
// 		if span := sentry.TransactionFromContext(ctx); span != nil {
// 			scope.SetSpan(span)
// 		}
// 		fn(scope)
// 	})
// }

// // getEnv retrieves environment variable with fallback default.
// func getEnv(key, defaultValue string) string {
// 	if value := os.Getenv(key); value != "" {
// 		return value
// 	}
// 	return defaultValue
// }
