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

// S3Store implements Store backed by MinIO or any S3-compatible service.
type S3Store struct {
	client        *minio.Client
	releaseBucket string
	patchBucket   string
}

// NewS3Store creates a new S3-compatible storage backend.
func NewS3Store(endpoint, accessKeyID, secretAccessKey, releaseBucket, patchBucket string, useSSL bool) (*S3Store, error) {
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKeyID, secretAccessKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create minio client: %w", err)
	}
	return &S3Store{client: client, releaseBucket: releaseBucket, patchBucket: patchBucket}, nil
}

func (s *S3Store) BackendName() string { return "S3/MinIO" }

func (s *S3Store) GeneratePresignedUploadURL(ctx context.Context, objectKey string, isPublic bool, expiry time.Duration) (string, error) {
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

func (s *S3Store) GeneratePublicDownloadURL(ctx context.Context, objectKey string) (string, error) {
	endpoint := s.client.EndpointURL()
	return fmt.Sprintf("%s/%s/%s", endpoint.String(), s.patchBucket, objectKey), nil
}

func (s *S3Store) UploadObject(ctx context.Context, objectKey string, reader io.Reader, size int64, contentType string, isPublic bool) error {
	bucket := s.releaseBucket
	if isPublic {
		bucket = s.patchBucket
	}
	_, err := s.client.PutObject(ctx, bucket, objectKey, reader, size, minio.PutObjectOptions{ContentType: contentType})
	if err != nil {
		return fmt.Errorf("failed to upload object: %w", err)
	}
	return nil
}

func (s *S3Store) GetObject(ctx context.Context, objectKey string, isPublic bool) (io.ReadCloser, error) {
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

// PresignedURL parses a presigned URL string.
func PresignedURL(raw string) (*url.URL, error) {
	return url.Parse(raw)
}
