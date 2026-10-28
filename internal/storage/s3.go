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
	uploadProxy   UploadProxyConfig
}

// NewS3Store creates a new S3-compatible storage backend.
func NewS3Store(endpoint, accessKeyID, secretAccessKey, releaseBucket, patchBucket string, useSSL bool, uploadProxy ...UploadProxyConfig) (*S3Store, error) {
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKeyID, secretAccessKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create minio client: %w", err)
	}
	store := &S3Store{client: client, releaseBucket: releaseBucket, patchBucket: patchBucket}
	if len(uploadProxy) > 0 {
		store.uploadProxy = uploadProxy[0]
	}
	return store, nil
}

func (s *S3Store) BackendName() string { return "S3/MinIO" }

// GeneratePresignedUploadURL issues a bounded multipart POST grant at the API
// facade; the facade streams the bytes into S3 using the server's credentials.
func (s *S3Store) GeneratePresignedUploadURL(ctx context.Context, objectKey string, isPublic bool, expiry time.Duration, size ...int64) (string, error) {
	if len(size) != 1 {
		return "", fmt.Errorf("S3 multipart upload requires a declared size")
	}
	scope := "releases"
	if isPublic {
		scope = "patches"
	}
	return s.uploadProxy.generate(scope, objectKey, expiry, size[0])
}
func (s *S3Store) ValidateUploadToken(scope, objectKey, token string, expires int64, size ...int64) bool {
	return len(size) == 1 && s.uploadProxy.validate(scope, objectKey, token, expires, size[0])
}

// GeneratePresignedDownloadURL grants short-lived read access to the selected bucket.
func (s *S3Store) GeneratePresignedDownloadURL(ctx context.Context, objectKey string, isPublic bool, expiry time.Duration) (string, error) {
	bucket := s.releaseBucket
	if isPublic {
		bucket = s.patchBucket
	}
	u, err := s.client.PresignedGetObject(ctx, bucket, objectKey, expiry, nil)
	if err != nil {
		return "", fmt.Errorf("failed to generate download URL: %w", err)
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
