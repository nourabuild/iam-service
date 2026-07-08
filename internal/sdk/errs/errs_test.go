package errs

import (
	"errors"
	"net/http"
	"testing"
)

func TestWrap(t *testing.T) {
	root := errors.New("database unavailable")

	err := Wrap(root, http.StatusServiceUnavailable, "service_unavailable")

	if err.Status != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d", http.StatusServiceUnavailable, err.Status)
	}
	if err.Key != "service_unavailable" {
		t.Fatalf("expected key service_unavailable, got %s", err.Key)
	}
	if !errors.Is(err, root) {
		t.Fatal("expected wrapped root error")
	}
}

func TestWithFields(t *testing.T) {
	err := WithFields(New(http.StatusBadRequest, "validation_failed"), map[string]string{
		"email": "required",
	})

	if err.Fields["email"] != "required" {
		t.Fatalf("expected email field to be required, got %s", err.Fields["email"])
	}
}

func TestFrom(t *testing.T) {
	appErr := New(http.StatusConflict, "conflict")

	got, ok := From(appErr)
	if !ok {
		t.Fatal("expected app error to be found")
	}
	if got != appErr {
		t.Fatal("expected original app error")
	}

	if _, ok := From(errors.New("plain error")); ok {
		t.Fatal("did not expect plain error to be an app error")
	}
}
