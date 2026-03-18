package sentry

import (
	"time"

	githubsentry "github.com/getsentry/sentry-go"
)

type mockSentryService struct{}

func NewMockSentryService() SentryRepository {
	return &mockSentryService{}
}

// CaptureException implements [SentryRepository].
func (m *mockSentryService) CaptureException(err error) {}

// CaptureMessage implements [SentryRepository].
func (m *mockSentryService) CaptureMessage(message string) {
}

// Close implements [SentryRepository].
func (m *mockSentryService) Close() {
}

// Flush implements [SentryRepository].
func (m *mockSentryService) Flush(timeout time.Duration) bool {
	return true
}

// Recover implements [SentryRepository].
func (m *mockSentryService) Recover() {
}

// WithScope implements [SentryRepository].
func (m *mockSentryService) WithScope(fn func(scope *Scope)) {
	if fn == nil {
		return
	}

	fn(githubsentry.NewScope())
}
