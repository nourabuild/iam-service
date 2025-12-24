// Package minio provides S3-compatible object storage using MinIO.
package minio

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/disintegration/imaging"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

var (
	ErrUploadFailed   = errors.New("upload failed")
	ErrDownloadFailed = errors.New("download failed")
	ErrDeleteFailed   = errors.New("delete failed")
	ErrNotFound       = errors.New("object not found")
	ErrInvalidImage   = errors.New("invalid image")
)

type Size string

const (
	SizeSmall  Size = "small"
	SizeMedium Size = "medium"
	SizeLarge  Size = "large"
)

var sizeDimensions = map[Size]int{
	SizeSmall:  64,
	SizeMedium: 128,
	SizeLarge:  256,
}

type MinioService struct {
	client     *minio.Client
	bucketName string
	endpoint   string
	useSSL     bool
}

func NewMinioService() *MinioService {
	endpoint := getEnv("MINIO_ENDPOINT", "localhost:9000")
	accessKey := getEnv("MINIO_ACCESS_KEY", "minioadmin")
	secretKey := getEnv("MINIO_SECRET_KEY", "minioadmin")
	bucketName := getEnv("MINIO_BUCKET", "iam-service")
	useSSL := os.Getenv("MINIO_USE_SSL") == "true"

	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		return nil
	}

	return &MinioService{
		client:     client,
		bucketName: bucketName,
		endpoint:   endpoint,
		useSSL:     useSSL,
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func (s *MinioService) EnsureBucket(ctx context.Context) error {
	exists, err := s.client.BucketExists(ctx, s.bucketName)
	if err != nil {
		return err
	}
	if !exists {
		return s.client.MakeBucket(ctx, s.bucketName, minio.MakeBucketOptions{})
	}
	return nil
}

func (s *MinioService) Upload(ctx context.Context, objectName string, reader io.Reader, size int64, contentType string) error {
	_, err := s.client.PutObject(ctx, s.bucketName, objectName, reader, size, minio.PutObjectOptions{
		ContentType: contentType,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUploadFailed, err)
	}
	return nil
}

func (s *MinioService) Download(ctx context.Context, objectName string) (io.ReadCloser, error) {
	obj, err := s.client.GetObject(ctx, s.bucketName, objectName, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDownloadFailed, err)
	}
	if _, err = obj.Stat(); err != nil {
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrDownloadFailed, err)
	}
	return obj, nil
}

func (s *MinioService) Delete(ctx context.Context, objectName string) error {
	if err := s.client.RemoveObject(ctx, s.bucketName, objectName, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("%w: %v", ErrDeleteFailed, err)
	}
	return nil
}

func (s *MinioService) GetPresignedURL(ctx context.Context, objectName string, expiry time.Duration) (string, error) {
	u, err := s.client.PresignedGetObject(ctx, s.bucketName, objectName, expiry, nil)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

func (s *MinioService) GetPublicURL(objectName string) string {
	scheme := "http"
	if s.useSSL {
		scheme = "https"
	}
	return (&url.URL{
		Scheme: scheme,
		Host:   s.endpoint,
		Path:   "/" + s.bucketName + "/" + objectName,
	}).String()
}

// UploadWithVariants uploads the original image and creates size variants (small, medium, large)
func (s *MinioService) UploadWithVariants(ctx context.Context, objectName string, reader io.Reader, contentType string) error {
	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUploadFailed, err)
	}

	if err := s.Upload(ctx, objectName, bytes.NewReader(data), int64(len(data)), contentType); err != nil {
		return err
	}

	for size, dim := range sizeDimensions {
		resized, err := resizeImage(data, dim)
		if err != nil {
			continue
		}
		variantName := variantObjectName(objectName, size)
		_ = s.Upload(ctx, variantName, bytes.NewReader(resized), int64(len(resized)), "image/jpeg")
	}
	return nil
}

// DeleteWithVariants deletes the original and all size variants
func (s *MinioService) DeleteWithVariants(ctx context.Context, objectName string) error {
	if err := s.Delete(ctx, objectName); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	for size := range sizeDimensions {
		_ = s.Delete(ctx, variantObjectName(objectName, size))
	}
	return nil
}

func variantObjectName(objectName string, size Size) string {
	ext := filepath.Ext(objectName)
	return strings.TrimSuffix(objectName, ext) + "_" + string(size) + ext
}

func resizeImage(data []byte, dim int) ([]byte, error) {
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidImage, err)
	}
	resized := imaging.Fit(img, dim, dim, imaging.Lanczos)
	var buf bytes.Buffer
	if err := imaging.Encode(&buf, resized, imaging.JPEG, imaging.JPEGQuality(85)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
