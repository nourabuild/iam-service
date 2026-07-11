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
	base := New(http.StatusBadRequest, "validation_failed")
	fields := map[string]string{
		"email": "required",
	}
	err := WithFields(base, fields)

	if err.Fields["email"] != "required" {
		t.Fatalf("expected email field to be required, got %s", err.Fields["email"])
	}
	if base.Fields != nil {
		t.Fatal("WithFields mutated the base error")
	}
	fields["email"] = "changed"
	if err.Fields["email"] != "required" {
		t.Fatal("WithFields retained the caller's mutable map")
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
