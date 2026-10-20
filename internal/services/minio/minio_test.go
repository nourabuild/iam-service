package minio

import (
	"context"
	"errors"
	"image"
	"image/color"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateSquare(t *testing.T) {
	if err := ValidateSquare(image.NewRGBA(image.Rect(0, 0, 100, 100))); err != nil {
		t.Fatalf("square image rejected: %v", err)
	}
	if err := ValidateSquare(image.NewRGBA(image.Rect(0, 0, 200, 100))); err == nil {
		t.Fatal("non-square image accepted")
	}
	if err := ValidateSquare(image.NewRGBA(image.Rect(0, 0, 0, 0))); err == nil {
		t.Fatal("zero-sized image accepted")
	}
	if err := ValidateSquare(nil); err == nil {
		t.Fatal("nil image accepted")
	}
}

func TestResizeAvatar(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})

	resized, err := ResizeAvatar(img, " PNG ")
	if err != nil {
		t.Fatalf("ResizeAvatar returned error: %v", err)
	}
	for size, dimension := range avatarDimensions {
		if len(resized[size]) == 0 {
			t.Errorf("%s avatar is empty (dimension %d)", size, dimension)
		}
	}
	if _, err := ResizeAvatar(nil, "png"); err == nil {
		t.Fatal("nil image accepted")
	}
	if _, err := ResizeAvatar(img, "webp"); err == nil {
		t.Fatal("unsupported format accepted")
	}
	if _, err := ResizeAvatar(img, "jpg"); err != nil {
		t.Fatalf("jpg format rejected: %v", err)
	}
}

func TestGetReturnsErrNotFound(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	client, err := New(Options{Config: Config{
		Endpoint: strings.TrimPrefix(server.URL, "http://"),
		Region:   "us-east-1",
	}})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	reader, err := client.Get(context.Background(), "avatars", "missing.png")
	if reader != nil {
		if closeErr := reader.Close(); closeErr != nil {
			t.Errorf("closing unexpected reader: %v", closeErr)
		}
		t.Fatal("Get returned a reader for a missing object")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get error = %v, want ErrNotFound", err)
	}
}
