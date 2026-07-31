package mailtrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/nourabuild/iam-service/internal/sdk/config"
)

func TestSendPasswordResetEmailUsesConfiguredEndpoint(t *testing.T) {
	var got mailtrapTemplateRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/custom/send" {
			t.Errorf("request path = %q, want /custom/send", r.URL.Path)
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer api-token" {
			t.Errorf("Authorization = %q", auth)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decoding request: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	client := NewMailtrapService(config.Mailtrap{
		APIToken:         "api-token",
		APIURL:           server.URL + "/custom/send",
		TemplateUUID:     "template-id",
		SenderEmail:      "noreply@example.com",
		SenderName:       "IAM Service",
		PasswordResetURL: "https://app.example.com/reset?source=email",
	})

	if err := client.SendPasswordResetEmail(context.Background(), "user@example.com", "a token&value"); err != nil {
		t.Fatalf("SendPasswordResetEmail returned error: %v", err)
	}
	if got.TemplateUUID != "template-id" {
		t.Fatalf("template UUID = %q", got.TemplateUUID)
	}
	if got.TemplateVariables.UserEmail != "user@example.com" {
		t.Fatalf("template user email = %q", got.TemplateVariables.UserEmail)
	}
	wantLink := "https://app.example.com/reset?source=email&token=a+token%26value"
	if got.TemplateVariables.PassResetLink != wantLink {
		t.Fatalf("reset link = %q, want %q", got.TemplateVariables.PassResetLink, wantLink)
	}
}

func TestSendPasswordResetEmailHonorsCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	client := NewMailtrapService(config.Mailtrap{
		APIToken:         "api-token",
		APIURL:           server.URL,
		SenderEmail:      "noreply@example.com",
		PasswordResetURL: "https://app.example.com/reset",
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := client.SendPasswordResetEmail(ctx, "user@example.com", "token")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestSendPasswordResetEmailDoesNotFollowRedirects(t *testing.T) {
	var redirected atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Store(true)
	}))
	defer target.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()

	client := NewMailtrapService(config.Mailtrap{
		APIToken:         "api-token",
		APIURL:           source.URL,
		TemplateUUID:     "template-id",
		SenderEmail:      "noreply@example.com",
		PasswordResetURL: "https://app.example.com/reset",
	})

	err := client.SendPasswordResetEmail(context.Background(), "user@example.com", "token")
	if err == nil {
		t.Fatal("expected redirect response to fail")
	}
	if redirected.Load() {
		t.Fatal("mail client followed a redirect and could expose its bearer token")
	}
}
