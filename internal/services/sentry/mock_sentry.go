package sentry

import "time"

type mockSentryService struct{}

func NewMockSentryService() SentryRepository {
	return &mockSentryService{}
}

// CaptureException implements [SentryRepository].
func (m *mockSentryService) CaptureException(err error) {}

// CaptureMessage implements [SentryRepository].
func (m *mockSentryService) CaptureMessage(message string) {
	panic("unimplemented")
}

// Close implements [SentryRepository].
func (m *mockSentryService) Close() {
	panic("unimplemented")
}

// Flush implements [SentryRepository].
func (m *mockSentryService) Flush(timeout time.Duration) bool {
	panic("unimplemented")
}

// Recover implements [SentryRepository].
func (m *mockSentryService) Recover() {
	panic("unimplemented")
}

// WithScope implements [SentryRepository].
func (m *mockSentryService) WithScope(fn func(scope *Scope)) {}
