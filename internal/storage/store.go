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

// GenerateDeviceEncryptedPatchStorageKey creates a cache key for a patch
// encrypted specifically for a device. deviceIDHash must be a non-reversible
// hash of the updater device/client ID, not the raw ID.
func GenerateDeviceEncryptedPatchStorageKey(appID string, releaseID int, patchNumber int, platform, arch, patchHash, deviceIDHash, keyID string) string {
	return fmt.Sprintf("apps/%s/releases/%d/patches/%d/%s/%s/encrypted/%s/%s/%s.aesgcm", appID, releaseID, patchNumber, platform, arch, deviceIDHash, keyID, patchHash)
}
