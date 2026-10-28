package artifactgateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMirrorAndProxyRoutes(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "shorebird", "engine"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "shorebird", "engine", "sdk.zip"), []byte("sdk-payload"), 0600); err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/flutter_infra_release/flutter/engine/sdk.zip" || r.URL.RawQuery != "check=1" {
			t.Errorf("unexpected upstream URL: %s", r.URL)
		}
		http.Redirect(w, r, "/artifacts/shorebird/engine/sdk.zip", http.StatusFound)
	}))
	defer proxy.Close()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "api") })
	handler, err := Wrap(next, root, proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	client := server.Client()
	response, err := client.Get(server.URL + "/download.flutter.io/flutter_infra_release/flutter/engine/sdk.zip?check=1")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || string(data) != "sdk-payload" {
		t.Fatalf("redirect/download failed: %s %q %v", response.Status, data, err)
	}
	request, _ := http.NewRequest(http.MethodGet, server.URL+"/artifacts/shorebird/engine/sdk.zip", nil)
	request.Header.Set("Range", "bytes=0-2")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	data, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusPartialContent || string(data) != "sdk" {
		t.Fatalf("range download: %s %q", response.Status, data)
	}
	for _, path := range []string{"/api/v1/apps", "/health"} {
		response, err = client.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		data, _ = io.ReadAll(response.Body)
		response.Body.Close()
		if string(data) != "api" {
			t.Fatalf("API routing changed: %s", data)
		}
	}
}

func TestMirrorRejectsWritesTraversalAndSymlinks(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "shorebird"), 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	symlinkErr := os.Symlink(outside, filepath.Join(root, "shorebird", "link"))
	handler, err := Wrap(http.NotFoundHandler(), root, "")
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{"/artifacts/shorebird/../secret", "/artifacts/shorebird/%2e%2e/secret", "/artifacts/shorebird/", "/artifacts/secret", "/artifacts/shorebird/a%5csecret"}
	if symlinkErr == nil {
		paths = append(paths, "/artifacts/shorebird/link")
	}
	for _, path := range paths {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("path %s accepted: %d", path, w.Code)
		}
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/artifacts/shorebird/write", strings.NewReader("bad")))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("write accepted: %d", w.Code)
	}
	if _, err = os.Stat(filepath.Join(root, "shorebird", "write")); !os.IsNotExist(err) {
		t.Fatal("created upload")
	}
}

func TestInvalidConfiguration(t *testing.T) {
	for _, upstream := range []string{"file:///tmp", "http://user:secret@host", "http://host?q=1", "not-a-url"} {
		if _, err := Wrap(http.NotFoundHandler(), "", upstream); err == nil {
			t.Errorf("accepted %s", upstream)
		}
	}
	if _, err := Wrap(http.NotFoundHandler(), t.TempDir(), ""); err == nil {
		t.Fatal("accepted directory without mirror")
	}
}
