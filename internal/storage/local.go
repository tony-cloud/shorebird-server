package storage

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// LocalStore implements Store using the local filesystem.
// Release artifacts go under <baseDir>/releases/; patch artifacts
// under <baseDir>/patches/ (publicly served by the built-in upload
// handler — no presigned URLs needed).
type LocalStore struct {
	baseDir string
	// serverBaseURL is the external URL of this server (e.g. http://localhost:8080).
	// Used when generating download URLs for device-side patch checks.
	serverBaseURL string
	uploadSecret  string
}

// NewLocalStore creates a local-filesystem storage backend.
// baseDir is created automatically if it does not exist.
func NewLocalStore(baseDir, serverBaseURL, uploadSecret string) (*LocalStore, error) {
	abs, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, fmt.Errorf("local storage: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(abs, "releases"), 0o755); err != nil {
		return nil, fmt.Errorf("local storage: create releases dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(abs, "patches"), 0o755); err != nil {
		return nil, fmt.Errorf("local storage: create patches dir: %w", err)
	}
	if serverBaseURL == "" {
		serverBaseURL = "http://localhost:8080"
	}
	return &LocalStore{baseDir: abs, serverBaseURL: serverBaseURL, uploadSecret: uploadSecret}, nil
}

func (s *LocalStore) BackendName() string { return "Local filesystem" }

// GeneratePresignedUploadURL returns a server endpoint URL that the
// CLI can POST the artifact to.  The upload handler (registered on
// the router) writes the file to disk.
func (s *LocalStore) GeneratePresignedUploadURL(_ context.Context, objectKey string, isPublic bool, _ time.Duration) (string, error) {
	scope := "releases"
	if isPublic {
		scope = "patches"
	}
	base := fmt.Sprintf("%s/storage/upload/%s/%s", s.serverBaseURL, scope, objectKey)
	if s.uploadSecret == "" {
		return base, nil
	}
	expires := time.Now().Add(30 * time.Minute).Unix()
	return fmt.Sprintf("%s?expires=%d&token=%s", base, expires, s.signUpload(scope, objectKey, expires)), nil
}

// GeneratePublicDownloadURL returns a public download URL for a patch.
func (s *LocalStore) GeneratePublicDownloadURL(_ context.Context, objectKey string) (string, error) {
	return fmt.Sprintf("%s/storage/dl/patches/%s", s.serverBaseURL, objectKey), nil
}

// UploadObject writes data directly to the local filesystem.
func (s *LocalStore) UploadObject(_ context.Context, objectKey string, reader io.Reader, _ int64, _ string, isPublic bool) error {
	scope := "releases"
	if isPublic {
		scope = "patches"
	}
	target, err := s.objectPath(scope, objectKey)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("local storage: %w", err)
	}
	f, err := os.Create(target)
	if err != nil {
		return fmt.Errorf("local storage: %w", err)
	}
	defer f.Close()
	if _, err := io.Copy(f, reader); err != nil {
		return fmt.Errorf("local storage: write: %w", err)
	}
	return nil
}

// GetObject reads an object from the local filesystem.
func (s *LocalStore) GetObject(_ context.Context, objectKey string, isPublic bool) (io.ReadCloser, error) {
	scope := "releases"
	if isPublic {
		scope = "patches"
	}
	target, err := s.objectPath(scope, objectKey)
	if err != nil {
		return nil, err
	}
	return os.Open(target)
}

// BaseDir returns the absolute base directory.
func (s *LocalStore) BaseDir() string { return s.baseDir }

func (s *LocalStore) ValidateUploadToken(scope, objectKey, token string, expires int64) bool {
	if s.uploadSecret == "" {
		return true
	}
	if token == "" || expires <= time.Now().Unix() {
		return false
	}
	expected := s.signUpload(scope, objectKey, expires)
	return hmac.Equal([]byte(token), []byte(expected))
}

func (s *LocalStore) signUpload(scope, objectKey string, expires int64) string {
	mac := hmac.New(sha256.New, []byte(s.uploadSecret))
	io.WriteString(mac, scope)
	io.WriteString(mac, "\n")
	io.WriteString(mac, objectKey)
	io.WriteString(mac, "\n")
	io.WriteString(mac, strconv.FormatInt(expires, 10))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *LocalStore) objectPath(scope, objectKey string) (string, error) {
	if objectKey == "" || filepath.IsAbs(objectKey) {
		return "", fmt.Errorf("local storage: invalid object key")
	}
	cleanKey := filepath.Clean(filepath.FromSlash(objectKey))
	if cleanKey == "." || cleanKey == ".." || strings.HasPrefix(cleanKey, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("local storage: invalid object key")
	}
	root := filepath.Join(s.baseDir, scope)
	target := filepath.Join(root, cleanKey)
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("local storage: invalid object key")
	}
	return target, nil
}
