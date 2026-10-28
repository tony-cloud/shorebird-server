package handlers

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/shorebird-server/internal/models"
	"github.com/shorebird-server/internal/storage"
)

func TestS3MultipartFacadeHTTPMatchesCLIAndEnforcesUploadGrants(t *testing.T) {
	f := newAPIFixture(t)
	var mu sync.Mutex
	objects := map[string][]byte{}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("location") {
			w.Header().Set("Content-Type", "application/xml")
			io.WriteString(w, `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">us-east-1</LocationConstraint>`)
			return
		}
		if r.Method == http.MethodPut {
			var reader io.Reader = r.Body
			if strings.Contains(r.Header.Get("Content-Encoding"), "aws-chunked") || strings.HasPrefix(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING-") {
				reader = httputil.NewChunkedReader(reader)
			}
			data, err := io.ReadAll(reader)
			if err != nil {
				http.Error(w, "incomplete S3 payload", http.StatusBadRequest)
				return
			}
			mu.Lock()
			objects[r.URL.Path] = append([]byte(nil), data...)
			mu.Unlock()
			sum := md5.Sum(data)
			w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:])+`"`)
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == http.MethodGet {
			mu.Lock()
			data, ok := objects[r.URL.Path]
			mu.Unlock()
			if !ok {
				http.NotFound(w, r)
				return
			}
			if strings.HasPrefix(r.URL.Path, "/private-releases/") && r.URL.Query().Get("X-Amz-Signature") == "" {
				http.Error(w, "private bucket", 403)
				return
			}
			w.Write(data)
			return
		}
		http.Error(w, "unsupported S3 operation", http.StatusMethodNotAllowed)
	}))
	t.Cleanup(origin.Close)
	f.server.Close()
	api := httptest.NewUnstartedServer(nil)
	apiBase := "http://" + api.Listener.Addr().String()
	backend, err := storage.NewStore(storage.Config{Type: "s3", ServerBaseURL: apiBase, UploadSecret: "facade-upload-secret", S3Endpoint: strings.TrimPrefix(origin.URL, "http://"), S3AccessKey: "test-access", S3SecretKey: "test-secret", S3ReleaseBucket: "private-releases", S3PatchBucket: "public-patches"})
	if err != nil {
		t.Fatal(err)
	}
	api.Config.Handler = NewRouter(f.auth, f.db, backend, nil, apiBase, PatchDeliveryConfig{}, SigningConfig{MasterKey: testSigningMasterKey})
	api.Start()
	t.Cleanup(api.Close)
	f.server = api
	f.objects = backend
	keyID, publicPEM, publicKey := f.signingKey(t)
	baseline := []byte("baseline")
	status, data := f.multipart(t, fmt.Sprintf("/api/v1/apps/%s/releases/%d/artifacts", f.app.ID, f.release.ID), f.owner, map[string]string{"arch": "xcarchive", "platform": "ios", "hash": strings.Repeat("a", 64), "size": strconv.Itoa(len(baseline)), "filename": "baseline.zip", "signing": fmt.Sprintf(`{"mode":"managed","key_id":%d}`, keyID)})
	if status != 201 {
		t.Fatalf("S3 registration %d %s", status, data)
	}
	var registered models.CreateReleaseArtifactResponse
	if err := json.Unmarshal(data, &registered); err != nil {
		t.Fatal(err)
	}
	grant, err := url.Parse(registered.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(registered.URL, apiBase+"/storage/upload/releases/") || grant.Query().Get("size") != "8" || grant.Query().Get("token") == "" || grant.Query().Get("X-Amz-Algorithm") != "" {
		t.Fatalf("S3 upload does not use bounded multipart facade: %s", registered.URL)
	}
	upload := func(target *url.URL, payload []byte) int {
		t.Helper()
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		file, err := writer.CreateFormFile("file", "baseline.zip")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		status, contents := f.request(t, "POST", target.RequestURI(), "", writer.FormDataContentType(), body.String())
		if status >= 500 {
			t.Logf("upload error: %d %s", status, contents)
		}
		return status
	}
	for _, mutation := range []func(*url.URL){
		func(u *url.URL) { q := u.Query(); q.Set("size", "9"); u.RawQuery = q.Encode() },
		func(u *url.URL) { q := u.Query(); q.Del("size"); u.RawQuery = q.Encode() },
		func(u *url.URL) {
			q := u.Query()
			q.Set("expires", strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10))
			u.RawQuery = q.Encode()
		},
		func(u *url.URL) { q := u.Query(); q.Del("token"); u.RawQuery = q.Encode() },
		func(u *url.URL) { u.Path += "-other" },
		func(u *url.URL) { u.Path = strings.Replace(u.Path, "/releases/", "/patches/", 1) },
	} {
		changed := *grant
		mutation(&changed)
		if status := upload(&changed, baseline); status != 403 {
			t.Fatalf("modified upload grant accepted: %d %s", status, &changed)
		}
	}
	if status := upload(grant, baseline); status != 200 {
		t.Fatalf("multipart S3 upload failed: %d", status)
	}
	// The private object contains only file bytes, never the multipart wrapper.
	objectPath := "/private-releases/" + strings.TrimPrefix(grant.Path, "/storage/upload/releases/")
	mu.Lock()
	stored := append([]byte(nil), objects[objectPath]...)
	mu.Unlock()
	if !bytes.Equal(stored, baseline) {
		t.Fatalf("S3 stored wrong bytes: %q", stored)
	}
	for _, payload := range [][]byte{[]byte("short"), []byte("oversized")} {
		if status := upload(grant, payload); status != 400 {
			t.Fatalf("incorrect upload size was not rejected: payload=%q status=%d", payload, status)
		}
		mu.Lock()
		stored = append([]byte(nil), objects[objectPath]...)
		mu.Unlock()
		if !bytes.Equal(stored, baseline) {
			t.Fatalf("invalid-size request replaced published object: %q", stored)
		}
	}
	status, data = f.request(t, "GET", fmt.Sprintf("/api/v1/apps/%s/releases/%d/artifacts", f.app.ID, f.release.ID), f.owner, "", "")
	if status != 200 {
		t.Fatalf("S3 artifact listing %d %s", status, data)
	}
	var listing struct {
		Artifacts []models.ReleaseArtifact `json:"artifacts"`
	}
	if err := json.Unmarshal(data, &listing); err != nil {
		t.Fatal(err)
	}
	if len(listing.Artifacts) != 1 || listing.Artifacts[0].Signing == nil || listing.Artifacts[0].Signing.PublicKeyPEM == nil || *listing.Artifacts[0].Signing.PublicKeyPEM != publicPEM {
		t.Fatalf("S3 signing metadata lost: %s", data)
	}
	response, err := api.Client().Get(listing.Artifacts[0].URL)
	if err != nil {
		t.Fatal(err)
	}
	downloaded, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || !bytes.Equal(downloaded, baseline) {
		t.Fatalf("S3 private download failed: %d %q", response.StatusCode, downloaded)
	}
	// Patch uploads use the same multipart facade and inherit the baseline key.
	patchBytes := []byte("patch")
	finalHash := strings.Repeat("b", 64)
	status, data = f.multipart(t, fmt.Sprintf("/api/v1/apps/%s/patches/%d/artifacts", f.app.ID, f.patch.ID), f.owner, map[string]string{"arch": "aarch64", "platform": "ios", "hash": finalHash, "size": "5"})
	if status != 201 {
		t.Fatalf("S3 patch registration %d %s", status, data)
	}
	var patch models.CreatePatchArtifactResponse
	if err := json.Unmarshal(data, &patch); err != nil {
		t.Fatal(err)
	}
	patchGrant, err := url.Parse(patch.URL)
	if err != nil {
		t.Fatal(err)
	}
	if status := upload(patchGrant, patchBytes); status != 200 {
		t.Fatalf("S3 patch upload failed: %d", status)
	}
	artifacts, err := f.db.GetPatchArtifacts(context.Background(), f.patch.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 1 || artifacts[0].HashSignature == nil {
		t.Fatal("S3 managed patch signature missing")
	}
	verifyRSASignature(t, publicKey, []byte(finalHash), *artifacts[0].HashSignature)
	channel, err := f.db.CreateChannel(context.Background(), f.app.ID, "stable")
	if err != nil {
		t.Fatal(err)
	}
	status, data = f.request(t, "POST", fmt.Sprintf("/api/v1/apps/%s/patches/promote", f.app.ID), f.owner, "application/json", fmt.Sprintf(`{"patch_id":%d,"channel_id":%d}`, f.patch.ID, channel.ID))
	if status != 204 {
		t.Fatalf("S3 promotion %d %s", status, data)
	}
	status, data = f.request(t, "POST", "/api/v1/patches/check", "", "application/json", fmt.Sprintf(`{"app_id":"%s","release_version":"%s","platform":"ios","arch":"aarch64","channel":"stable","nonce":"%s"}`, f.app.ID, f.release.Version, uuid.NewString()))
	var check models.PatchCheckResponse
	if err := json.Unmarshal(data, &check); err != nil {
		t.Fatal(err)
	}
	if status != 200 || !check.PatchAvailable || check.Patch == nil || check.Authentication == nil {
		t.Fatalf("S3 delivery %d %s", status, data)
	}
	response, err = api.Client().Get(check.Patch.DownloadURL)
	if err != nil {
		t.Fatal(err)
	}
	downloaded, err = io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || !bytes.Equal(downloaded, patchBytes) {
		t.Fatalf("S3 patch bytes differ: %d %q", response.StatusCode, downloaded)
	}
}
