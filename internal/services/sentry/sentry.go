package sentry

import (
	"os"
	"time"

	"github.com/getsentry/sentry-go"
)

// Package sentry provides error tracking and monitoring using Sentry.
//
// Sentry helps you monitor and fix crashes in real time.
// When something goes wrong in production, Sentry captures the error
// and sends it to your Sentry dashboard so you can investigate.
//
// Setup:
//  1. Create a Sentry account at https://sentry.io
//  2. Create a new project and get your DSN
//  3. Set the SENTRY_DSN environment variable

// =============================================================================
// Sentry Service
// =============================================================================

// SentryService wraps the Sentry SDK for easy error tracking.
// Create one instance at app startup and reuse it everywhere.
type SentryService struct {
	initialized bool
}

// Scope is an alias for sentry.Scope to avoid importing sentry-go directly.
type Scope = sentry.Scope

// Level is an alias for sentry.Level to avoid importing sentry-go directly.
type Level = sentry.Level

// Level constants for convenience.
const (
	LevelDebug   Level = sentry.LevelDebug
	LevelInfo    Level = sentry.LevelInfo
	LevelWarning Level = sentry.LevelWarning
	LevelError   Level = sentry.LevelError
	LevelFatal   Level = sentry.LevelFatal
)

// NewSentryService creates and initializes a new SentryService.
//
// It reads configuration from environment variables:
//   - SENTRY_DSN:         Your Sentry project DSN (required)
//   - SENTRY_ENVIRONMENT: Environment name like "production" or "staging" (optional)
//
// Example:
//
//	sentryService := sentry.NewSentryService()
//	defer sentryService.Close() // Always close at app shutdown
func NewSentryService() *SentryService {
	dsn := os.Getenv("SENTRY_DSN")
	environment := os.Getenv("SENTRY_ENVIRONMENT")
	if environment == "" {
		environment = "development"
	}

	// Initialize Sentry SDK
	err := sentry.Init(sentry.ClientOptions{
		Dsn:         dsn,
		Environment: environment,

		// Set to true to print debug info (disable in production)
		Debug: environment == "development",

		// Sample rate for error events (1.0 = 100% of errors)
		SampleRate: 1.0,
	})

	return &SentryService{
		initialized: err == nil,
	}
}

// =============================================================================
// Public Methods
// =============================================================================

// CaptureException sends an error to Sentry.
//
// Use this when you catch an error that you want to track.
//
// Example:
//
//	user, err := db.GetUser(id)
//	if err != nil {
//	    sentryService.CaptureException(err)
//	    return nil, err
//	}
func (s *SentryService) CaptureException(err error) {
	if !s.initialized || err == nil {
		return
	}
	sentry.CaptureException(err)
}

// CaptureMessage sends a message to Sentry.
//
// Use this for important events that aren't errors.
//
// Example:
//
//	sentryService.CaptureMessage("User completed onboarding")
func (s *SentryService) CaptureMessage(message string) {
	if !s.initialized {
		return
	}
	sentry.CaptureMessage(message)
}

// Flush waits for all events to be sent to Sentry.
//
// Returns true if all events were sent before the timeout.
// Call this before your app shuts down to avoid losing events.
//
// Example:
//
//	if !sentryService.Flush(2 * time.Second) {
//	    log.Println("Warning: some events may not have been sent to Sentry")
//	}
func (s *SentryService) Flush(timeout time.Duration) bool {
	if !s.initialized {
		return true
	}
	return sentry.Flush(timeout)
}

// Close flushes pending events and shuts down the Sentry client.
//
// Always call this when your app is shutting down.
//
// Example:
//
//	func main() {
//	    sentryService := sentry.NewSentryService()
//	    defer sentryService.Close()
//
//	    // ... rest of your app
//	}
func (s *SentryService) Close() {
	s.Flush(2 * time.Second)
}

// Recover captures a panic and sends it to Sentry.
//
// Use this with defer at the start of goroutines.
//
// Example:
//
//	go func() {
//	    defer sentryService.Recover()
//	    // ... code that might panic
//	}()
func (s *SentryService) Recover() {
	if !s.initialized {
		return
	}
	if r := recover(); r != nil {
		sentry.CurrentHub().Recover(r)
		sentry.Flush(2 * time.Second)
	}
}

// WithScope runs a function with extra context attached to errors.
//
// Use this to add extra info like user ID or request data.
//
// Example:
//
//	sentryService.WithScope(func(scope *sentry.Scope) {
//	    scope.SetUser(sentry.User{ID: userID})
//	    scope.SetTag("endpoint", "/api/users")
//	    scope.SetExtra("request_body", requestBody)
//	    scope.SetLevel(sentry.LevelWarning)
//
//	    sentryService.CaptureException(err)
//	})
func (s *SentryService) WithScope(fn func(scope *sentry.Scope)) {
	if !s.initialized {
		return
	}
	sentry.WithScope(fn)
}
