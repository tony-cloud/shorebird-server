package storage

import (
	"context"
	"fmt"
	"io"
	"time"
)

// Store is the storage backend interface.
type Store interface {
	GeneratePresignedUploadURL(ctx context.Context, objectKey string, isPublic bool, expiry time.Duration) (string, error)
	GeneratePublicDownloadURL(ctx context.Context, objectKey string) (string, error)
	UploadObject(ctx context.Context, objectKey string, reader io.Reader, size int64, contentType string, isPublic bool) error
	GetObject(ctx context.Context, objectKey string, isPublic bool) (io.ReadCloser, error)
	BackendName() string
}

// GenerateReleaseStorageKey creates a standardized storage key for releases.
func GenerateReleaseStorageKey(appID, version, platform, arch, filename string) string {
	return fmt.Sprintf("apps/%s/releases/%s/%s/%s/%s", appID, version, platform, arch, filename)
}

// GeneratePatchStorageKey creates a standardized storage key for patches.
func GeneratePatchStorageKey(appID string, releaseID int, patchNumber int, platform, arch, filename string) string {
	return fmt.Sprintf("apps/%s/releases/%d/patches/%d/%s/%s/%s", appID, releaseID, patchNumber, platform, arch, filename)
}
