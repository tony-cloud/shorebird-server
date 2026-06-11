package storage

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Service handles object storage operations (MinIO / S3 compatible).
type Service struct {
	client        *minio.Client
	releaseBucket string
	patchBucket   string
}

// NewService creates a new storage service.
func NewService(endpoint, accessKeyID, secretAccessKey, releaseBucket, patchBucket string, useSSL bool) (*Service, error) {
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKeyID, secretAccessKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create minio client: %w", err)
	}

	return &Service{
		client:        client,
		releaseBucket: releaseBucket,
		patchBucket:   patchBucket,
	}, nil
}

// GeneratePresignedUploadURL creates a presigned URL for uploading an object.
func (s *Service) GeneratePresignedUploadURL(ctx context.Context, objectKey string, isPublic bool, expiry time.Duration) (string, error) {
	bucket := s.releaseBucket
	if isPublic {
		bucket = s.patchBucket
	}

	u, err := s.client.PresignedPutObject(ctx, bucket, objectKey, expiry)
	if err != nil {
		return "", fmt.Errorf("failed to generate presigned URL: %w", err)
	}
	return u.String(), nil
}

// GeneratePublicDownloadURL creates a public download URL for a patch artifact.
func (s *Service) GeneratePublicDownloadURL(ctx context.Context, objectKey string) (string, error) {
	// For MinIO, construct the public URL directly
	// In production with a CDN, this would be a CDN URL
	endpoint := s.client.EndpointURL()
	return fmt.Sprintf("%s/%s/%s", endpoint.String(), s.patchBucket, objectKey), nil
}

// UploadObject directly uploads data to storage.
func (s *Service) UploadObject(ctx context.Context, objectKey string, reader io.Reader, size int64, contentType string, isPublic bool) error {
	bucket := s.releaseBucket
	if isPublic {
		bucket = s.patchBucket
	}

	opts := minio.PutObjectOptions{
		ContentType: contentType,
	}
	if size > 0 {
		// Let minio handle unknown size
	}

	_, err := s.client.PutObject(ctx, bucket, objectKey, reader, size, opts)
	if err != nil {
		return fmt.Errorf("failed to upload object: %w", err)
	}
	return nil
}

// GetObject retrieves an object from storage.
func (s *Service) GetObject(ctx context.Context, objectKey string, isPublic bool) (io.ReadCloser, error) {
	bucket := s.releaseBucket
	if isPublic {
		bucket = s.patchBucket
	}

	obj, err := s.client.GetObject(ctx, bucket, objectKey, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get object: %w", err)
	}
	return obj, nil
}

// GenerateReleaseStorageKey creates a standardized storage key for releases.
func GenerateReleaseStorageKey(appID, version, platform, arch, filename string) string {
	return fmt.Sprintf("apps/%s/releases/%s/%s/%s/%s", appID, version, platform, arch, filename)
}

// GeneratePatchStorageKey creates a standardized storage key for patches.
func GeneratePatchStorageKey(appID string, releaseID int, patchNumber int, platform, arch, filename string) string {
	return fmt.Sprintf("apps/%s/releases/%d/patches/%d/%s/%s/%s", appID, releaseID, patchNumber, platform, arch, filename)
}

// PresignedURL returns a parsed presigned URL.
func PresignedURL(raw string) (*url.URL, error) {
	return url.Parse(raw)
}
