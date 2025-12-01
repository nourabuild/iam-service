package sentry

import (
	"log"
	"os"
	"time"

	"github.com/getsentry/sentry-go"
)

// Service provides Sentry error tracking functionality
type SentryService struct {
	initialized bool
}

// New creates and initializes a new Sentry service
func NewSentryService() *SentryService {
	dsn := os.Getenv("SENTRY_DSN")
	if dsn == "" {
		log.Println("SENTRY_DSN not set, Sentry disabled")
		return &SentryService{initialized: false}
	}

	environment := os.Getenv("SENTRY_ENVIRONMENT")
	if environment == "" {
		environment = "development"
	}

	err := sentry.Init(sentry.ClientOptions{
		Dsn:              dsn,
		Environment:      environment,
		TracesSampleRate: 1.0,
		EnableTracing:    true,
	})
	if err != nil {
		log.Printf("Sentry initialization failed: %v", err)
		return &SentryService{initialized: false}
	}

	log.Println("Sentry initialized successfully")
	return &SentryService{initialized: true}
}

// CaptureException captures an error and sends it to Sentry
func (s *SentryService) CaptureException(err error) {
	if !s.initialized {
		return
	}
	sentry.CaptureException(err)
}

// CaptureMessage captures a message and sends it to Sentry
func (s *SentryService) CaptureMessage(message string) {
	if !s.initialized {
		return
	}
	sentry.CaptureMessage(message)
}

// Flush waits for all events to be sent to Sentry
func (s *SentryService) Flush(timeout time.Duration) bool {
	if !s.initialized {
		return true
	}
	return sentry.Flush(timeout)
}

// Close flushes and closes the Sentry client
func (s *SentryService) Close() {
	s.Flush(2 * time.Second)
}

// Recover captures a panic and sends it to Sentry
func (s *SentryService) Recover() {
	if !s.initialized {
		return
	}
	if err := recover(); err != nil {
		sentry.CurrentHub().Recover(err)
		sentry.Flush(2 * time.Second)
	}
}

// WithScope executes a function with a new Sentry scope
func (s *SentryService) WithScope(fn func(scope *sentry.Scope)) {
	if !s.initialized {
		return
	}
	sentry.WithScope(fn)
}
