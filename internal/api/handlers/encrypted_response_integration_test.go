package handlers

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/shorebird-server/internal/models"
)

// Optional fixture export exercises the same Go HTTP path with a real native
// compressed diff supplied by the Rust test owner. Exported keys are TEST ONLY.
func TestAuthenticatedEncryptedPatchDeliveryHTTP(t *testing.T) {
	transport := []byte("test-only compressed transport fixture")
	installed := []byte("test-only reconstructed native binary")
	if input := os.Getenv("SHOREBIRD_ENCRYPTED_RESPONSE_TRANSPORT"); input != "" {
		var err error
		transport, err = os.ReadFile(input)
		if err != nil {
			t.Fatal(err)
		}
		installed, err = os.ReadFile(os.Getenv("SHOREBIRD_ENCRYPTED_RESPONSE_OUTPUT"))
		if err != nil {
			t.Fatal(err)
		}
	}
	secret := []byte("test-only-server-delivery-secret")
	f := newAPIFixture(t)
	f.configure(t, testSigningMasterKey, PatchDeliveryConfig{
		EncryptionMode: PatchDeliveryEncryptionPerDeviceAESGCM, AESSecret: secret, CacheEncryptedPatches: true,
	})
	keyID, publicPEM, public := f.signingKey(t)
	status, data := f.multipart(t, fmt.Sprintf("/api/v1/apps/%s/releases/%d/artifacts", f.app.ID, f.release.ID), f.owner, map[string]string{
		"arch": "app", "platform": "macos", "hash": strings.Repeat("1", 64), "size": "8", "filename": "App",
		"signing": fmt.Sprintf(`{"mode":"managed","key_id":%d}`, keyID),
	})
	if status != http.StatusCreated {
		t.Fatalf("native baseline registration: %d %s", status, data)
	}
	status, data = f.multipart(t, fmt.Sprintf("/api/v1/apps/%s/patches/%d/artifacts", f.app.ID, f.patch.ID), f.owner, map[string]string{
		"arch": "aarch64", "platform": "macos", "hash": sha256Hex(installed), "size": fmt.Sprint(len(transport)),
	})
	if status != http.StatusCreated {
		t.Fatalf("native patch registration: %d %s", status, data)
	}
	var artifact models.CreatePatchArtifactResponse
	if err := json.Unmarshal(data, &artifact); err != nil {
		t.Fatal(err)
	}
	upload, err := url.Parse(artifact.URL)
	if err != nil {
		t.Fatal(err)
	}
	status, data = f.request(t, http.MethodPost, upload.RequestURI(), "", "application/octet-stream", string(transport))
	if status != http.StatusOK {
		t.Fatalf("private patch upload: %d %s", status, data)
	}
	channel, err := f.db.CreateChannel(context.Background(), f.app.ID, "stable")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.PromotePatch(context.Background(), f.patch.ID, channel.ID); err != nil {
		t.Fatal(err)
	}
	clientID := "test-only-native-client"
	request := models.PatchCheckRequest{
		AppID: f.app.ID.String(), ReleaseVersion: f.release.Version, Platform: "macos", Arch: "aarch64",
		Channel: "stable", Nonce: uuid.NewString(), ClientID: &clientID, AcceptEncryptedPatch: true,
	}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	status, data = f.request(t, http.MethodPost, "/api/v1/patches/check", "", "application/json", string(body))
	if status != http.StatusOK {
		t.Fatalf("encrypted check: %d %s", status, data)
	}
	var response models.PatchCheckResponse
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatal(err)
	}
	if response.Patch == nil || response.Patch.Encryption == nil || response.Authentication == nil {
		t.Fatalf("encrypted authenticated offer missing fields: %s", data)
	}
	payload, err := base64.StdEncoding.DecodeString(response.Authentication.Payload)
	if err != nil {
		t.Fatal(err)
	}
	verifyRSASignature(t, public, payload, response.Authentication.Signature)
	var signed signedPatchCheckPayload
	if err := json.Unmarshal(payload, &signed); err != nil {
		t.Fatal(err)
	}
	if signed.Patch == nil || signed.Patch.Encryption == nil || *signed.Patch.Encryption != *response.Patch.Encryption {
		t.Fatalf("encryption metadata is not covered by the signed response: %s", payload)
	}
	download, err := url.Parse(response.Patch.DownloadURL)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(download.Path, "/storage/dl/patches/") || download.Query().Get("token") == "" {
		t.Fatalf("ciphertext download is not an expiring scoped grant: %s", download.Path)
	}
	status, ciphertext := f.request(t, http.MethodGet, download.RequestURI(), "", "", "")
	if status != http.StatusOK || bytes.Equal(ciphertext, transport) {
		t.Fatalf("ciphertext download failed: %d", status)
	}
	if !bytes.Equal(decryptPatchForTest(t, secret, response.Patch.Encryption, ciphertext), transport) {
		t.Fatal("download did not decrypt to the uploaded compressed transport")
	}
	unsigned := *download
	unsigned.RawQuery = ""
	status, _ = f.request(t, http.MethodGet, unsigned.RequestURI(), "", "", "")
	if status != http.StatusForbidden {
		t.Fatalf("anonymous ciphertext access: %d", status)
	}
	// The original is private even when its old predictable patch URL is known.
	original := *upload
	original.Path = strings.Replace(original.Path, "/storage/upload/releases/", "/storage/dl/patches/", 1)
	original.RawQuery = ""
	status, _ = f.request(t, http.MethodGet, original.RequestURI(), "", "", "")
	if status != http.StatusForbidden {
		t.Fatalf("anonymous original access: %d", status)
	}
	if target := os.Getenv("SHOREBIRD_ENCRYPTED_RESPONSE_FIXTURE"); target != "" {
		aad, err := base64.RawURLEncoding.DecodeString(response.Patch.Encryption.AAD)
		if err != nil {
			t.Fatal(err)
		}
		fixture := map[string]interface{}{
			"public_key_pem": publicPEM, "request": request, "response": response,
			"public_key_der_base64": base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PublicKey(public)),
			"derived_key_base64":    base64.StdEncoding.EncodeToString(derivePatchDeliveryKey(secret, string(aad))),
			"ciphertext_base64":     base64.StdEncoding.EncodeToString(ciphertext),
			"transport_base64":      base64.StdEncoding.EncodeToString(transport),
			"installed_base64":      base64.StdEncoding.EncodeToString(installed),
		}
		if input := os.Getenv("SHOREBIRD_ENCRYPTED_RESPONSE_BASE"); input != "" {
			base, err := os.ReadFile(input)
			if err != nil {
				t.Fatal(err)
			}
			fixture["base_binary_base64"] = base64.StdEncoding.EncodeToString(base)
			fixture["target_binary_base64"] = base64.StdEncoding.EncodeToString(installed)
		}
		serialized, err := json.MarshalIndent(fixture, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, serialized, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
