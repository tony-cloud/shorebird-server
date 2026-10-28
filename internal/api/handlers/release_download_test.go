package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/shorebird-server/internal/models"
	"github.com/shorebird-server/internal/storage"
)

func TestReleaseArtifactDownloadHTTPUsesPrivateLocalSignedURL(t *testing.T) {
	f := newAPIFixture(t)
	key := storage.GenerateReleaseStorageKey(f.app.ID.String(), f.release.Version, "ios", "xcarchive", "baseline +#?.zip")
	content := []byte("private baseline archive")
	if err := f.objects.UploadObject(context.Background(), key, bytes.NewReader(content), int64(len(content)), "application/octet-stream", false); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.CreateReleaseArtifact(context.Background(), f.release.ID, "xcarchive", "ios", strings.Repeat("a", 64), key, int64(len(content)), false, nil); err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/api/v1/apps/%s/releases/%d/artifacts?platform=ios&arch=xcarchive", f.app.ID, f.release.ID)
	var download *url.URL
	for _, tc := range []struct {
		token  string
		status int
	}{{"", 401}, {f.outsider, 403}, {f.owner, 200}, {f.reader, 200}} {
		status, data := f.request(t, "GET", path, tc.token, "", "")
		if status != tc.status {
			t.Fatalf("artifact access %d want %d: %s", status, tc.status, data)
		}
		if status != 200 {
			continue
		}
		var listing struct {
			Artifacts []models.ReleaseArtifact `json:"artifacts"`
		}
		if err := json.Unmarshal(data, &listing); err != nil {
			t.Fatal(err)
		}
		if len(listing.Artifacts) != 1 {
			t.Fatalf("wrong client artifact schema %s", data)
		}
		parsed, err := url.Parse(listing.Artifacts[0].URL)
		if err != nil {
			t.Fatal(err)
		}
		download = parsed
		if parsed.Query().Get("token") == "" || parsed.Query().Get("expires") == "" || parsed.Path != "/storage/dl/releases/"+key {
			t.Fatalf("release URL is not scoped and signed: %s", parsed)
		}
	}
	if download == nil {
		t.Fatal("no authorized download URL issued")
	}
	status, data := f.request(t, "GET", download.RequestURI(), "", "", "")
	if status != 200 || !bytes.Equal(data, content) {
		t.Fatalf("signed local download %d %s", status, data)
	}
	// Private objects require their own expiring read grant, even if the path is known.
	unsigned := *download
	unsigned.RawQuery = ""
	status, data = f.request(t, "GET", unsigned.RequestURI(), "", "", "")
	if status != 403 {
		t.Fatalf("unsigned private download accepted: %d %s", status, data)
	}
	modified := *download
	q := modified.Query()
	q.Set("expires", strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10))
	modified.RawQuery = q.Encode()
	status, data = f.request(t, "GET", modified.RequestURI(), "", "", "")
	if status != 403 {
		t.Fatalf("expired private download accepted: %d %s", status, data)
	}
	modified = *download
	modified.Path += "-other"
	status, data = f.request(t, "GET", modified.RequestURI(), "", "", "")
	if status != 403 {
		t.Fatalf("cross-object grant accepted: %d %s", status, data)
	}
	modified = *download
	modified.Path = strings.Replace(modified.Path, "/releases/", "/unknown/", 1)
	status, data = f.request(t, "GET", modified.RequestURI(), "", "", "")
	if status != 404 {
		t.Fatalf("alternate scope bypass accepted: %d %s", status, data)
	}
	upload, err := f.objects.GeneratePresignedUploadURL(context.Background(), key, false, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	parsedUpload, err := url.Parse(upload)
	if err != nil {
		t.Fatal(err)
	}
	modified = *download
	modified.RawQuery = parsedUpload.RawQuery
	status, data = f.request(t, "GET", modified.RequestURI(), "", "", "")
	if status != 403 {
		t.Fatalf("upload grant accepted as read grant: %d %s", status, data)
	}
}

func TestReleaseArtifactDownloadHTTPUsesActualS3PresignedGet(t *testing.T) {
	f := newAPIFixture(t)
	key := storage.GenerateReleaseStorageKey(f.app.ID.String(), f.release.Version, "ios", "xcarchive", "baseline.zip")
	content := []byte("private object at S3 origin")
	fakeS3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("location") {
			w.Header().Set("Content-Type", "application/xml")
			io.WriteString(w, `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">us-east-1</LocationConstraint>`)
			return
		}
		q := r.URL.Query()
		if r.Method != "GET" || r.URL.Path != "/private-releases/"+key || q.Get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256" || q.Get("X-Amz-Signature") == "" || !strings.HasPrefix(q.Get("X-Amz-Credential"), "test-access/") {
			http.Error(w, "unsigned or wrongly scoped S3 request", http.StatusForbidden)
			return
		}
		w.Write(content)
	}))
	t.Cleanup(fakeS3.Close)
	s3, err := storage.NewS3Store(strings.TrimPrefix(fakeS3.URL, "http://"), "test-access", "test-secret", "private-releases", "public-patches", false)
	if err != nil {
		t.Fatal(err)
	}
	f.objects = s3
	f.configure(t, nil, PatchDeliveryConfig{})
	if _, err := f.db.CreateReleaseArtifact(context.Background(), f.release.ID, "xcarchive", "ios", strings.Repeat("a", 64), key, int64(len(content)), false, nil); err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/api/v1/apps/%s/releases/%d/artifacts", f.app.ID, f.release.ID)
	for _, tc := range []struct {
		token  string
		status int
	}{{"", 401}, {f.outsider, 403}, {f.owner, 200}, {f.reader, 200}} {
		status, data := f.request(t, "GET", path, tc.token, "", "")
		if status != tc.status {
			t.Fatalf("S3 artifact access %d want %d: %s", status, tc.status, data)
		}
		if status != 200 {
			continue
		}
		var listing struct {
			Artifacts []models.ReleaseArtifact `json:"artifacts"`
		}
		if err := json.Unmarshal(data, &listing); err != nil {
			t.Fatal(err)
		}
		if len(listing.Artifacts) != 1 {
			t.Fatalf("wrong client artifact schema: %s", data)
		}
		download, err := url.Parse(listing.Artifacts[0].URL)
		if err != nil {
			t.Fatal(err)
		}
		expires, err := strconv.Atoi(download.Query().Get("X-Amz-Expires"))
		if err != nil || expires != 1800 {
			t.Fatalf("unexpected S3 read expiry: %s", download)
		}
		if !strings.HasPrefix(download.String(), fakeS3.URL+"/private-releases/") || strings.Contains(download.Path, "/storage/dl/") {
			t.Fatalf("synthetic local URL returned for S3: %s", download)
		}
		response, err := f.server.Client().Get(download.String())
		if err != nil {
			t.Fatal(err)
		}
		contents, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != 200 || !bytes.Equal(contents, content) {
			t.Fatalf("S3 signed download: %d %s", response.StatusCode, contents)
		}
	}
	// The API's local storage route must not proxy private S3 objects without a grant.
	status, data := f.request(t, "GET", "/storage/dl/releases/"+key, "", "", "")
	if status != 403 {
		t.Fatalf("S3 private object exposed through API proxy: %d %s", status, data)
	}
}
