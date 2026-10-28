package handlers

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/shorebird-server/internal/storage"
)

func TestRequestLoggingRedactsQueryWithoutChangingSignedDownload(t *testing.T) {
	store, err := storage.NewLocalStore(t.TempDir(), "https://updates.test", "test-only-download-signing-secret")
	if err != nil {
		t.Fatal(err)
	}
	key := "apps/test/releases/1/patches/1/macos/aarch64/dlc.vmcode"
	content := []byte("private original patch")
	if err := store.UploadObject(context.Background(), key, bytes.NewReader(content), int64(len(content)), "application/octet-stream", false); err != nil {
		t.Fatal(err)
	}
	grant, err := store.GeneratePresignedDownloadURL(context.Background(), key, false, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	download, err := url.Parse(grant)
	if err != nil {
		t.Fatal(err)
	}
	query := download.Query()
	query.Set("signature", "test-only-query-signature")
	query.Set("unknown_future_secret", "test-only-future-secret")
	download.RawQuery = query.Encode()

	var logs bytes.Buffer
	router := chi.NewRouter()
	router.Use(pathOnlyRequestLogger(log.New(&logs, "", 0)))
	storageHandler := NewStorageHandler(store)
	router.Get("/storage/dl/{scope}/*", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != download.RawQuery || r.RequestURI != download.RequestURI() {
			t.Error("logging changed the request used to validate its download grant")
		}
		storageHandler.Download(w, r)
	})
	request := httptest.NewRequest(http.MethodGet, download.RequestURI(), nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), content) {
		t.Fatalf("signed request stopped working: status=%d body=%q", response.Code, response.Body.String())
	}
	if !strings.Contains(logs.String(), download.EscapedPath()) || !strings.Contains(logs.String(), "200") {
		t.Fatalf("request path and status missing from log: %s", logs.String())
	}
	for _, secret := range []string{query.Get("token"), query.Get("signature"), query.Get("unknown_future_secret"), "expires=", "token=", "signature=", "unknown_future_secret="} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("request log exposed query data %q", secret)
		}
	}
}
