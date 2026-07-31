// Package minio provides a client for interacting with MinIO object storage.
package minio

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"math"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	_ "image/gif"
)

type AvatarSize string

const (
	AvatarSmall  AvatarSize = "small"
	AvatarMedium AvatarSize = "medium"
	AvatarLarge  AvatarSize = "large"
)

var avatarDimensions = map[AvatarSize]int{
	AvatarSmall:  64,
	AvatarMedium: 128,
	AvatarLarge:  256,
}

// AspectRatioValidationHelper validates that the image is roughly square (1:1 aspect ratio).
func AspectRatioValidationHelper(img image.Image) error {
	bounds := img.Bounds()
	w := bounds.Dx()
	h := bounds.Dy()

	if w == 0 || h == 0 {
		return fmt.Errorf("invalid image dimensions: %dx%d", w, h)
	}

	ratio := float64(w) / float64(h)
	if ratio < 0.9 || ratio > 1.1 {
		return fmt.Errorf("image must be square (1:1 aspect ratio), got %dx%d (ratio %.2f)", w, h, ratio)
	}

	return nil
}

// ResizeAvatar resizes an image to all avatar sizes using nearest-neighbor scaling.
// format must be "png" or "jpeg".
func ResizeAvatar(img image.Image, format string) (map[AvatarSize][]byte, error) {
	if img == nil || img.Bounds().Dx() <= 0 || img.Bounds().Dy() <= 0 {
		return nil, fmt.Errorf("avatar image must have non-zero dimensions")
	}
	format = strings.ToLower(strings.TrimSpace(format))
	results := make(map[AvatarSize][]byte, len(avatarDimensions))

	for size, dim := range avatarDimensions {
		resized := resizeNearestNeighbor(img, dim, dim)

		var buf bytes.Buffer
		switch format {
		case "png":
			if err := png.Encode(&buf, resized); err != nil {
				return nil, fmt.Errorf("encode png for %s: %w", size, err)
			}
		case "jpeg", "jpg":
			if err := jpeg.Encode(&buf, resized, &jpeg.Options{Quality: 90}); err != nil {
				return nil, fmt.Errorf("encode jpeg for %s: %w", size, err)
			}
		default:
			return nil, fmt.Errorf("unsupported format: %s", format)
		}

		results[size] = buf.Bytes()
	}

	return results, nil
}

// resizeNearestNeighbor scales src to dstW x dstH using nearest-neighbor interpolation.
func resizeNearestNeighbor(src image.Image, dstW, dstH int) image.Image {
	srcBounds := src.Bounds()
	srcW := srcBounds.Dx()
	srcH := srcBounds.Dy()

	dst := image.NewRGBA(image.Rect(0, 0, dstW, dstH))

	for y := range dstH {
		srcY := srcBounds.Min.Y + int(math.Floor(float64(y)*float64(srcH)/float64(dstH)))
		for x := range dstW {
			srcX := srcBounds.Min.X + int(math.Floor(float64(x)*float64(srcW)/float64(dstW)))
			dst.Set(x, y, src.At(srcX, srcY))
		}
	}

	return dst
}

type Config struct {
	Endpoint        string
	AccessKeyID     string
	SecretAccessKey string
	SSL             bool
	Region          string
}

type MinioService struct {
	client *minio.Client
}

type NewMinioServiceOptions struct {
	Config    Config
	PathStyle bool
}

func NewMinioService(opts NewMinioServiceOptions) (*MinioService, error) {
	bucketLookup := minio.BucketLookupAuto
	if opts.PathStyle {
		bucketLookup = minio.BucketLookupPath
	}

	client, err := minio.New(opts.Config.Endpoint, &minio.Options{
		Creds:        credentials.NewStaticV4(opts.Config.AccessKeyID, opts.Config.SecretAccessKey, ""),
		Secure:       opts.Config.SSL,
		Region:       opts.Config.Region,
		BucketLookup: bucketLookup,
	})
	if err != nil {
		return nil, err
	}

	return &MinioService{client: client}, nil
}

// Put uploads a blob to the bucket under key with the given contentType.
func (s *MinioService) Put(ctx context.Context, bucket, key string, reader io.Reader, size int64, contentType string) error {
	_, err := s.client.PutObject(ctx, bucket, key, reader, size, minio.PutObjectOptions{
		ContentType: contentType,
	})
	return err
}

// Get retrieves a blob from the bucket under key.
// If there is nothing there, returns nil and no error.
func (s *MinioService) Get(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
	obj, err := s.client.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}

	// Check if the object actually exists by reading its stat.
	_, err = obj.Stat()
	if err != nil {
		_ = obj.Close()
		if minio.ToErrorResponse(err).Code == minio.NoSuchKey {
			return nil, nil
		}
		return nil, err
	}

	return obj, nil
}

// Delete removes a blob from the bucket under key.
// Deleting where nothing exists does nothing and returns no error.
func (s *MinioService) Delete(ctx context.Context, bucket, key string) error {
	return s.client.RemoveObject(ctx, bucket, key, minio.RemoveObjectOptions{})
}
