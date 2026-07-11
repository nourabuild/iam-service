package minio

import (
	"image"
	"image/color"
	"testing"
)

func TestAspectRatioValidationHelper(t *testing.T) {
	if err := AspectRatioValidationHelper(image.NewRGBA(image.Rect(0, 0, 100, 100))); err != nil {
		t.Fatalf("square image rejected: %v", err)
	}
	if err := AspectRatioValidationHelper(image.NewRGBA(image.Rect(0, 0, 200, 100))); err == nil {
		t.Fatal("non-square image accepted")
	}
	if err := AspectRatioValidationHelper(image.NewRGBA(image.Rect(0, 0, 0, 0))); err == nil {
		t.Fatal("zero-sized image accepted")
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
}
