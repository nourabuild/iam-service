package sentry

import (
	"net/url"
	"testing"

	githubsentry "github.com/getsentry/sentry-go"
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
