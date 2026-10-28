package handlers

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/shorebird-server/internal/db"
	"github.com/shorebird-server/internal/models"
	"github.com/shorebird-server/internal/storage"
)

const (
	testReleaseVersion = "1.0.0+1"
	testArch           = "x64"
	testPlatform       = "windows"
)

func TestPatchCheckRemovesExpiredInstalledPatchWhenNoNewPatchExists(t *testing.T) {
	fixture := newPatchCheckFixture(t)
	fixture.createPatch(t, 1, time.Now().Add(-time.Hour))

	response := fixture.patchCheck(t, &models.PatchCheckRequest{
		ReleaseVersion:     testReleaseVersion,
		Platform:           testPlatform,
		Arch:               testArch,
		AppID:              fixture.appID.String(),
		Channel:            "stable",
		CurrentPatchNumber: intPtr(1),
	})

	if response.PatchAvailable {
		t.Fatalf("expected no patch, got %+v", response.Patch)
	}
	if response.RemovePatch == nil {
		t.Fatal("expected remove_patch metadata")
	}
	if response.RemovePatch.Number != 1 || response.RemovePatch.Reason != "offline_expired" {
		t.Fatalf("unexpected remove_patch: %+v", response.RemovePatch)
	}
	if !containsInt(response.RolledBackPatchNumbers, 1) {
		t.Fatalf("expected rolled_back_patch_numbers to contain 1, got %+v", response.RolledBackPatchNumbers)
	}
}

func TestPatchCheckServesNewPatchInsteadOfRemovingExpiredInstalledPatch(t *testing.T) {
	fixture := newPatchCheckFixture(t)
	fixture.createPatch(t, 1, time.Now().Add(-time.Hour))
	fixture.createPatch(t, 2, time.Now().Add(24*time.Hour))

	response := fixture.patchCheck(t, &models.PatchCheckRequest{
		ReleaseVersion:     testReleaseVersion,
		Platform:           testPlatform,
		Arch:               testArch,
		AppID:              fixture.appID.String(),
		Channel:            "stable",
		CurrentPatchNumber: intPtr(1),
	})

	if !response.PatchAvailable {
		t.Fatalf("expected patch 2 to be available, got remove=%+v", response.RemovePatch)
	}
	if response.Patch == nil || response.Patch.Number != 2 {
		t.Fatalf("expected patch number 2, got %+v", response.Patch)
	}
	if response.RemovePatch != nil {
		t.Fatalf("did not expect removal while a newer valid patch exists: %+v", response.RemovePatch)
	}
	if response.Patch.OfflineExpiresAt == nil {
		t.Fatal("expected offline_expires_at on patch metadata")
	}
}

func TestPatchCheckDoesNotServeExpiredPatchToUnpatchedDevice(t *testing.T) {
	fixture := newPatchCheckFixture(t)
	fixture.createPatch(t, 1, time.Now().Add(-time.Hour))

	response := fixture.patchCheck(t, &models.PatchCheckRequest{
		ReleaseVersion: testReleaseVersion,
		Platform:       testPlatform,
		Arch:           testArch,
		AppID:          fixture.appID.String(),
		Channel:        "stable",
	})

	if response.PatchAvailable {
		t.Fatalf("expected expired patch to be withheld, got %+v", response.Patch)
	}
	if response.RemovePatch != nil {
		t.Fatalf("unpatched devices should not receive removal metadata: %+v", response.RemovePatch)
	}
	if len(response.RolledBackPatchNumbers) != 0 {
		t.Fatalf("expected no rolled back numbers, got %+v", response.RolledBackPatchNumbers)
	}
}

type patchCheckFixture struct {
	handler   *DeviceHandler
	db        db.Store
	storage   storage.Store
	appID     uuid.UUID
	releaseID int
	channelID int
}

func newPatchCheckFixture(t *testing.T) *patchCheckFixture {
	t.Helper()
	database, err := db.NewSqliteStore(t.TempDir() + "/server.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	ctx := context.Background()
	orgID, err := database.CreateOrganization(ctx, "test org", "team")
	if err != nil {
		t.Fatal(err)
	}
	app, err := database.CreateApp(ctx, orgID, "license test")
	if err != nil {
		t.Fatal(err)
	}
	channel, err := database.CreateChannel(ctx, app.ID, "stable")
	if err != nil {
		t.Fatal(err)
	}
	release, err := database.CreateRelease(ctx, app.ID, testReleaseVersion, "flutter-rev", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	localStorage, err := storage.NewLocalStore(t.TempDir(), "http://updates.test", "test-only-download-secret")
	if err != nil {
		t.Fatal(err)
	}
	return &patchCheckFixture{
		handler: &DeviceHandler{
			DB:      database,
			Storage: localStorage,
		},
		db:        database,
		storage:   localStorage,
		appID:     app.ID,
		releaseID: release.ID,
		channelID: channel.ID,
	}
}

func (f *patchCheckFixture) createPatch(t *testing.T, number int, offlineExpiresAt time.Time) {
	t.Helper()
	ctx := context.Background()
	patch, err := f.db.CreatePatch(ctx, f.releaseID, number, nil)
	if err != nil {
		t.Fatal(err)
	}
	storageKey := storage.GeneratePatchStorageKey(f.appID.String(), f.releaseID, number, testPlatform, testArch, "dlc.vmcode")
	patchBytes := []byte(fmt.Sprintf("patch-%d-plaintext", number))
	hash := sha256Hex(patchBytes)
	if err := f.storage.UploadObject(ctx, storageKey, bytes.NewReader(patchBytes), int64(len(patchBytes)), "application/octet-stream", false); err != nil {
		t.Fatal(err)
	}
	expires := offlineExpiresAt.UTC()
	if _, err := f.db.CreatePatchArtifact(ctx, patch.ID, testArch, testPlatform, hash, storageKey, 128, nil, nil, &expires); err != nil {
		t.Fatal(err)
	}
	if err := f.db.PromotePatch(ctx, patch.ID, f.channelID); err != nil {
		t.Fatal(err)
	}
}

func TestPatchCheckRejectsPlaintextDowngradeWhenEncryptionRequired(t *testing.T) {
	fixture := newPatchCheckFixture(t)
	fixture.handler.PatchDelivery = PatchDeliveryConfig{EncryptionMode: PatchDeliveryEncryptionPerDeviceAESGCM, AESSecret: []byte("server-secret")}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/patches/check", strings.NewReader(`{"app_id":"`+fixture.appID.String()+`"}`))
	response := httptest.NewRecorder()
	fixture.handler.PatchCheck(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "encrypted_patch_capability_required") {
		t.Fatalf("downgrade accepted: %d %s", response.Code, response.Body.String())
	}
}

func TestEncryptedPatchTransportReadIsBounded(t *testing.T) {
	for _, size := range []int{15, 16, 17, 100} {
		reader := bytes.NewReader(bytes.Repeat([]byte{0x42}, size))
		data, err := readBoundedPatchBytes(reader, 16)
		if size > 16 {
			if err == nil || data != nil {
				t.Fatalf("accepted oversized encrypted transport of size %d", size)
			}
			if reader.Size()-int64(reader.Len()) != 17 {
				t.Fatalf("oversized transport read more than limit+1 bytes: %d", reader.Size()-int64(reader.Len()))
			}
		} else if err != nil || len(data) != size {
			t.Fatalf("valid transport read size=%d error=%v", size, err)
		}
	}
}

func TestPatchCheckEncryptsPatchPerDeviceAndCaches(t *testing.T) {
	fixture := newPatchCheckFixture(t)
	secret := []byte("server-secret")
	fixture.handler.PatchDelivery = PatchDeliveryConfig{
		EncryptionMode:        PatchDeliveryEncryptionPerDeviceAESGCM,
		AESSecret:             secret,
		CacheEncryptedPatches: true,
	}
	fixture.createPatch(t, 1, time.Now().Add(time.Hour))

	clientID := "device-1"
	request := &models.PatchCheckRequest{
		ReleaseVersion:       testReleaseVersion,
		Platform:             testPlatform,
		Arch:                 testArch,
		AppID:                fixture.appID.String(),
		Channel:              "stable",
		ClientID:             &clientID,
		AcceptEncryptedPatch: true,
	}

	first := fixture.patchCheck(t, request)
	second := fixture.patchCheck(t, request)

	if !first.PatchAvailable || first.Patch == nil || first.Patch.Encryption == nil {
		t.Fatalf("expected encrypted patch, got %+v", first)
	}
	if first.Patch.Encryption.Algorithm != "AES-256-GCM" {
		t.Fatalf("unexpected algorithm: %+v", first.Patch.Encryption)
	}
	if first.Patch.Encryption.CacheKey != second.Patch.Encryption.CacheKey {
		t.Fatalf("expected cached object reuse, got %q then %q", first.Patch.Encryption.CacheKey, second.Patch.Encryption.CacheKey)
	}
	if first.Patch.Encryption.EncryptedHash != second.Patch.Encryption.EncryptedHash {
		t.Fatalf("expected stable encrypted hash, got %q then %q", first.Patch.Encryption.EncryptedHash, second.Patch.Encryption.EncryptedHash)
	}
	if !strings.Contains(first.Patch.DownloadURL, "/encrypted/") {
		t.Fatalf("expected encrypted download URL, got %s", first.Patch.DownloadURL)
	}

	ciphertext := fixture.readObject(t, first.Patch.Encryption.CacheKey)
	if string(ciphertext) == "patch-1-plaintext" {
		t.Fatal("encrypted object should not equal plaintext patch bytes")
	}
	plaintext := decryptPatchForTest(t, secret, first.Patch.Encryption, ciphertext)
	if string(plaintext) != "patch-1-plaintext" {
		t.Fatalf("unexpected decrypted patch: %q", plaintext)
	}
	if _, err := decryptPatchForTestWithError([]byte("wrong-secret"), first.Patch.Encryption, ciphertext); err == nil {
		t.Fatal("expected wrong key to fail decrypting encrypted patch")
	}
}

func TestPatchCheckDerivesDifferentEncryptedPatchForDifferentDevices(t *testing.T) {
	fixture := newPatchCheckFixture(t)
	fixture.handler.PatchDelivery = PatchDeliveryConfig{
		EncryptionMode:        PatchDeliveryEncryptionPerDeviceAESGCM,
		AESSecret:             []byte("server-secret"),
		CacheEncryptedPatches: true,
	}
	fixture.createPatch(t, 1, time.Now().Add(time.Hour))

	clientA := "device-a"
	clientB := "device-b"
	responseA := fixture.patchCheck(t, &models.PatchCheckRequest{
		ReleaseVersion:       testReleaseVersion,
		Platform:             testPlatform,
		Arch:                 testArch,
		AppID:                fixture.appID.String(),
		Channel:              "stable",
		ClientID:             &clientA,
		AcceptEncryptedPatch: true,
	})
	responseB := fixture.patchCheck(t, &models.PatchCheckRequest{
		ReleaseVersion:       testReleaseVersion,
		Platform:             testPlatform,
		Arch:                 testArch,
		AppID:                fixture.appID.String(),
		Channel:              "stable",
		ClientID:             &clientB,
		AcceptEncryptedPatch: true,
	})

	if responseA.Patch.Encryption.CacheKey == responseB.Patch.Encryption.CacheKey {
		t.Fatalf("expected different cache keys, got %s", responseA.Patch.Encryption.CacheKey)
	}
	if responseA.Patch.Encryption.EncryptedHash == responseB.Patch.Encryption.EncryptedHash {
		t.Fatalf("expected different encrypted hashes, got %s", responseA.Patch.Encryption.EncryptedHash)
	}
}

func (f *patchCheckFixture) patchCheck(t *testing.T, request *models.PatchCheckRequest) models.PatchCheckResponse {
	t.Helper()
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/patches/check", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	f.handler.PatchCheck(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", recorder.Code, recorder.Body.String())
	}
	var response models.PatchCheckResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func containsInt(values []int, target int) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func (f *patchCheckFixture) readObject(t *testing.T, objectKey string) []byte {
	t.Helper()
	reader, err := f.storage.GetObject(context.Background(), objectKey, true)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	bytes, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return bytes
}

func decryptPatchForTest(t *testing.T, secret []byte, metadata *models.PatchEncryptionMetadata, ciphertext []byte) []byte {
	t.Helper()
	plaintext, err := decryptPatchForTestWithError(secret, metadata, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	return plaintext
}

func decryptPatchForTestWithError(secret []byte, metadata *models.PatchEncryptionMetadata, ciphertext []byte) ([]byte, error) {
	aadBytes, err := base64.RawURLEncoding.DecodeString(metadata.AAD)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.RawURLEncoding.DecodeString(metadata.Nonce)
	if err != nil {
		return nil, err
	}
	key := derivePatchDeliveryKey(secret, string(aadBytes))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, aadBytes)
}

func TestEncryptedDeliveryBindsActualTransportAndRepairsInconsistentCache(t *testing.T) {
	for _, cacheEnabled := range []bool{true, false} {
		t.Run(fmt.Sprintf("cache=%v", cacheEnabled), func(t *testing.T) {
			fixture := newPatchCheckFixture(t)
			secret := []byte("server-secret")
			fixture.handler.PatchDelivery = PatchDeliveryConfig{EncryptionMode: PatchDeliveryEncryptionPerDeviceAESGCM, AESSecret: secret, CacheEncryptedPatches: cacheEnabled}
			fixture.createPatch(t, 1, time.Now().Add(time.Hour))
			clientID := "same-device"
			request := &models.PatchCheckRequest{ReleaseVersion: testReleaseVersion, Platform: testPlatform, Arch: testArch, AppID: fixture.appID.String(), Channel: "stable", ClientID: &clientID, AcceptEncryptedPatch: true}
			first := fixture.patchCheck(t, request)
			firstMeta := first.Patch.Encryption
			firstCiphertext := fixture.readObject(t, firstMeta.CacheKey)
			// A publisher can produce different compressed/diff transport bytes for the
			// same final installed binary. Reupload without changing its registered hash.
			secondTransport := []byte("different compressed transport for the same final installed artifact")
			key := storage.GeneratePatchStorageKey(fixture.appID.String(), fixture.releaseID, 1, testPlatform, testArch, "dlc.vmcode")
			if err := fixture.storage.UploadObject(context.Background(), key, bytes.NewReader(secondTransport), int64(len(secondTransport)), "application/octet-stream", false); err != nil {
				t.Fatal(err)
			}
			second := fixture.patchCheck(t, request)
			secondMeta := second.Patch.Encryption
			if first.Patch.Hash != second.Patch.Hash {
				t.Fatal("test must preserve the final artifact hash")
			}
			if firstMeta.Nonce == secondMeta.Nonce || firstMeta.KeyID == secondMeta.KeyID || firstMeta.CacheKey == secondMeta.CacheKey {
				t.Fatalf("changed transport reused encryption context: first=%+v second=%+v", firstMeta, secondMeta)
			}
			firstAAD, err := base64.RawURLEncoding.DecodeString(firstMeta.AAD)
			if err != nil {
				t.Fatal(err)
			}
			secondAAD, err := base64.RawURLEncoding.DecodeString(secondMeta.AAD)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(derivePatchDeliveryKey(secret, string(firstAAD)), derivePatchDeliveryKey(secret, string(secondAAD))) {
				t.Fatal("changed transport reused AES key")
			}
			if !bytes.Contains(secondAAD, []byte("transport_hash="+sha256Hex(secondTransport))) || !strings.Contains(secondMeta.CacheKey, sha256Hex(secondTransport)) {
				t.Fatalf("transport digest absent from context or cache key: %s %s", secondAAD, secondMeta.CacheKey)
			}
			secondCiphertext := fixture.readObject(t, secondMeta.CacheKey)
			if secondMeta.EncryptedHash != sha256Hex(secondCiphertext) || secondMeta.AADHash != sha256Hex(secondAAD) {
				t.Fatal("metadata does not describe the stored ciphertext and AAD")
			}
			if !bytes.Equal(decryptPatchForTest(t, secret, secondMeta, secondCiphertext), secondTransport) {
				t.Fatal("new context decrypted stale transport bytes")
			}
			if string(decryptPatchForTest(t, secret, firstMeta, firstCiphertext)) != "patch-1-plaintext" {
				t.Fatal("old cache entry was replaced")
			}
			// A corrupt/partial cached object must never be returned with valid-looking
			// derived metadata; deterministic ciphertext allows exact cache validation.
			if err := fixture.storage.UploadObject(context.Background(), secondMeta.CacheKey, strings.NewReader("corrupt"), 7, "application/octet-stream", true); err != nil {
				t.Fatal(err)
			}
			repeat := fixture.patchCheck(t, request)
			repaired := fixture.readObject(t, repeat.Patch.Encryption.CacheKey)
			if repeat.Patch.Encryption.CacheKey != secondMeta.CacheKey || !bytes.Equal(repaired, secondCiphertext) || repeat.Patch.Encryption.EncryptedHash != sha256Hex(repaired) {
				t.Fatal("cache repair did not restore consistent ciphertext metadata")
			}
		})
	}
}
