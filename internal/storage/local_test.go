package storage

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

type failingUpload struct{}

func (failingUpload) Read(p []byte) (int, error) {
	return copy(p, []byte("partial")), errors.New("upload interrupted")
}
func TestLocalUploadFailurePreservesPreviouslyPublishedObject(t *testing.T) {
	store, err := NewLocalStore(t.TempDir(), "http://storage.test", "test-secret")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	key := "encrypted/cache.aesgcm"
	if err := store.UploadObject(ctx, key, strings.NewReader("complete ciphertext"), 19, "application/octet-stream", true); err != nil {
		t.Fatal(err)
	}
	if err := store.UploadObject(ctx, key, failingUpload{}, 100, "application/octet-stream", true); err == nil {
		t.Fatal("interrupted upload succeeded")
	}
	reader, err := store.GetObject(ctx, key, true)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "complete ciphertext" {
		t.Fatalf("failed upload replaced published ciphertext: %s", data)
	}
}
func TestLocalPrivateDownloadWithoutSigningSecretFailsClosed(t *testing.T) {
	store, err := NewLocalStore(t.TempDir(), "http://storage.test", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.GeneratePresignedDownloadURL(context.Background(), "private.zip", false, 0); err == nil {
		t.Fatal("unsigned private download generated")
	}
	if store.ValidateDownloadToken("releases", "private.zip", "", 0) {
		t.Fatal("unsigned private download accepted")
	}
}
