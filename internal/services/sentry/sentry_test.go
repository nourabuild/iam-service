package sentry

import (
	"net/url"
	"testing"

	githubsentry "github.com/getsentry/sentry-go"
	"github.com/nourabuild/iam-service/internal/sdk/config"
)

func TestScrubSentryRequestFiltersBearerParameters(t *testing.T) {
	event := &githubsentry.Event{Request: &githubsentry.Request{
		QueryString: "token=reset-secret&refresh_token=refresh-secret&view=profile",
	}}

	got := scrubSentryRequest(event)
	query, err := url.ParseQuery(got.Request.QueryString)
	if err != nil {
		t.Fatalf("parsing scrubbed query: %v", err)
	}
	if query.Get("token") != "[Filtered]" || query.Get("refresh_token") != "[Filtered]" {
		t.Fatalf("sensitive query values were not filtered: %s", got.Request.QueryString)
	}
	if query.Get("view") != "profile" {
		t.Fatalf("non-sensitive query value changed: %s", got.Request.QueryString)
	}
}

func TestSentryCallbacksRemoveCredentialData(t *testing.T) {
	options := clientOptions(config.Sentry{
		DSN:                    "https://public@example.com/1",
		SentryTracesSampleRate: 1,
	})

	callbacks := map[string]func(*githubsentry.Event, *githubsentry.EventHint) *githubsentry.Event{
		"error":       options.BeforeSend,
		"transaction": options.BeforeSendTransaction,
	}
	for name, callback := range callbacks {
		t.Run(name, func(t *testing.T) {
			event := &githubsentry.Event{Request: &githubsentry.Request{
				Data:    `{"password":"secret","refresh_token":"bearer"}`,
				Cookies: "session=secret",
				Headers: map[string]string{
					"Authorization":       "Bearer secret",
					"Cookie":              "session=secret",
					"proxy-authorization": "Bearer proxy-secret",
					"X-API-Key":           "api-secret",
					"X-Forwarded-For":     "192.0.2.1",
					"Content-Type":        "application/json",
					"X-Request-ID":        "request-id",
				},
				Env: map[string]string{"REMOTE_ADDR": "192.0.2.1"},
			}}

			got := callback(event, nil)
			if got.Request.Data != "" {
				t.Fatalf("request body was retained: %q", got.Request.Data)
			}
			if got.Request.Cookies != "" {
				t.Fatalf("cookies were retained: %q", got.Request.Cookies)
			}
			if got.Request.Env != nil {
				t.Fatalf("request environment was retained: %#v", got.Request.Env)
			}
			for _, key := range []string{
				"Authorization",
				"Cookie",
				"proxy-authorization",
				"X-API-Key",
				"X-Forwarded-For",
			} {
				if _, ok := got.Request.Headers[key]; ok {
					t.Fatalf("sensitive header %q was retained", key)
				}
			}
			if got.Request.Headers["Content-Type"] != "application/json" {
				t.Fatal("non-sensitive header was removed")
			}
			if got.Request.Headers["X-Request-ID"] != "request-id" {
				t.Fatal("request ID header was removed")
			}
		})
	}
}

func TestScrubSentryRequestHandlesNilEvent(t *testing.T) {
	if got := scrubSentryRequest(nil); got != nil {
		t.Fatalf("scrubSentryRequest(nil) = %#v", got)
	}
}

func TestScrubSentryRequestFiltersMalformedQuery(t *testing.T) {
	event := &githubsentry.Event{Request: &githubsentry.Request{QueryString: "token=%zz"}}
	if got := scrubSentryRequest(event).Request.QueryString; got != "[Filtered]" {
		t.Fatalf("malformed query = %q, want fully filtered", got)
	}
}
