package handlers

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/shorebird-server/internal/db"
	"github.com/shorebird-server/internal/models"
)

var testSigningMasterKey = bytes.Repeat([]byte{0x71}, 32)

func (f *apiFixture) configure(t *testing.T, masterKey []byte, delivery PatchDeliveryConfig) {
	t.Helper()
	f.server.Close()
	f.server = httptest.NewServer(NewRouter(f.auth, f.db, f.objects, nil, "", delivery, SigningConfig{MasterKey: masterKey}))
	t.Cleanup(f.server.Close)
}
func (f *apiFixture) multipart(t *testing.T, path, token string, fields map[string]string) (int, []byte) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return f.request(t, http.MethodPost, path, token, writer.FormDataContentType(), body.String())
}
func (f *apiFixture) signingKey(t *testing.T) (int, string, *rsa.PublicKey) {
	t.Helper()
	status, data := f.request(t, "GET", "/api/v1/apps/"+f.app.ID.String()+"/signing-key", f.owner, "", "")
	if status != 200 {
		t.Fatalf("signing key %d %s", status, data)
	}
	var response struct {
		Key struct {
			ID  int    `json:"id"`
			PEM string `json:"public_key_pem"`
		} `json:"signing_key"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatal(err)
	}
	var raw map[string]map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) != 1 || len(raw["signing_key"]) != 2 {
		t.Fatalf("signing key response exposes unexpected fields: %s", data)
	}
	block, _ := pem.Decode([]byte(response.Key.PEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatalf("invalid public PEM: %s", data)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok {
		t.Fatal("managed public key is not RSA")
	}
	return response.Key.ID, response.Key.PEM, key
}
func (f *apiFixture) registerBaseline(t *testing.T, signing string) {
	t.Helper()
	fields := map[string]string{"arch": "xcarchive", "platform": "ios", "hash": strings.Repeat("1", 64), "size": "8", "filename": "App"}
	if signing != "" {
		fields["signing"] = signing
	}
	status, data := f.multipart(t, fmt.Sprintf("/api/v1/apps/%s/releases/%d/artifacts", f.app.ID, f.release.ID), f.owner, fields)
	if status != 201 {
		t.Fatalf("baseline registration %d %s", status, data)
	}
}
func (f *apiFixture) registerManagedPatch(t *testing.T, hash string) models.CreatePatchArtifactResponse {
	t.Helper()
	status, data := f.multipart(t, fmt.Sprintf("/api/v1/apps/%s/patches/%d/artifacts", f.app.ID, f.patch.ID), f.owner, map[string]string{"arch": "aarch64", "platform": "ios", "hash": hash, "size": "5"})
	if status != 201 {
		t.Fatalf("patch registration %d %s", status, data)
	}
	var response models.CreatePatchArtifactResponse
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatal(err)
	}
	return response
}
func verifyRSASignature(t *testing.T, key *rsa.PublicKey, message []byte, signature string) {
	t.Helper()
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(message)
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("RSA signature verification: %v", err)
	}
}
func TestManagedSigningHTTPPersistsKeysPolicyAndSignsFinalArtifactHash(t *testing.T) {
	f := newAPIFixture(t)
	f.configure(t, testSigningMasterKey, PatchDeliveryConfig{})
	keyID, publicPEM, publicKey := f.signingKey(t)
	repeatID, repeatPEM, _ := f.signingKey(t)
	if repeatID != keyID || repeatPEM != publicPEM {
		t.Fatal("managed key changed across requests")
	}
	f.registerBaseline(t, fmt.Sprintf(`{"mode":"managed","key_id":%d}`, keyID))
	// Reopen the actual SQLite file and reconstruct the router; the private key must survive.
	f.server.Close()
	f.db.Close()
	reopened, err := db.NewSqliteStore(f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reopened.Close)
	f.db = reopened
	f.configure(t, testSigningMasterKey, PatchDeliveryConfig{})
	persistedID, persistedPEM, _ := f.signingKey(t)
	if persistedID != keyID || persistedPEM != publicPEM {
		t.Fatal("managed key changed after reopening database")
	}
	status, data := f.request(t, "GET", fmt.Sprintf("/api/v1/apps/%s/releases/%d/artifacts", f.app.ID, f.release.ID), f.owner, "", "")
	if status != 200 {
		t.Fatalf("artifact listing %d %s", status, data)
	}
	var listing struct {
		Artifacts []models.ReleaseArtifact `json:"artifacts"`
	}
	if err := json.Unmarshal(data, &listing); err != nil {
		t.Fatal(err)
	}
	if len(listing.Artifacts) != 1 || listing.Artifacts[0].Signing == nil {
		t.Fatalf("missing signing metadata %s", data)
	}
	policy := listing.Artifacts[0].Signing
	if policy.Mode != "managed" || policy.KeyID == nil || *policy.KeyID != keyID || policy.PublicKeyPEM == nil || *policy.PublicKeyPEM != publicPEM {
		t.Fatalf("wrong signing metadata: %s", data)
	}
	finalDigest := sha256.Sum256([]byte("final reconstructed artifact, not uploaded transport bytes"))
	hash := hex.EncodeToString(finalDigest[:])
	registered := f.registerManagedPatch(t, strings.ToUpper(hash))
	if registered.Hash != hash {
		t.Fatalf("hash not canonicalized: %s", registered.Hash)
	}
	stored, err := f.db.GetPatchArtifacts(context.Background(), f.patch.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 || stored[0].HashSignature == nil {
		t.Fatal("server did not persist managed signature")
	}
	verifyRSASignature(t, publicKey, []byte(hash), *stored[0].HashSignature)
	// The wire protocol signs hash text, not its decoded bytes.
	sig, _ := base64.StdEncoding.DecodeString(*stored[0].HashSignature)
	wrong := sha256.Sum256(finalDigest[:])
	if rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, wrong[:], sig) == nil {
		t.Fatal("signature unexpectedly uses decoded hash bytes")
	}
	// Only encrypted PKCS8 material is stored, and a different master key cannot unwrap it.
	record, err := f.db.GetSigningKeyByID(context.Background(), keyID)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := base64.StdEncoding.DecodeString(record.WrappedPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(wrapped); err == nil {
		t.Fatal("private key stored unencrypted")
	}
	f.configure(t, bytes.Repeat([]byte{0x72}, 32), PatchDeliveryConfig{})
	status, data = f.multipart(t, fmt.Sprintf("/api/v1/apps/%s/patches/%d/artifacts", f.app.ID, f.patch.ID), f.owner, map[string]string{"arch": "aarch64", "platform": "ios", "hash": hash, "size": "5"})
	if status != 503 || !bytes.Contains(data, []byte("managed_signing_unavailable")) {
		t.Fatalf("wrong master key did not fail closed: %d %s", status, data)
	}
}
func TestManagedSigningHTTPAuthorizationUnavailableAndPolicyChanges(t *testing.T) {
	f := newAPIFixture(t)
	path := "/api/v1/apps/" + f.app.ID.String() + "/signing-key"
	for _, tc := range []struct {
		token  string
		status int
	}{{"", 401}, {f.outsider, 403}, {f.reader, 403}, {f.owner, 503}} {
		status, data := f.request(t, "GET", path, tc.token, "", "")
		if status != tc.status {
			t.Fatalf("key auth %d want %d %s", status, tc.status, data)
		}
	}
	f.configure(t, testSigningMasterKey, PatchDeliveryConfig{})
	id, _, _ := f.signingKey(t)
	f.registerBaseline(t, fmt.Sprintf(`{"mode":"managed","key_id":%d}`, id))
	// A key belonging to another app cannot become this baseline's trust anchor.
	otherApp, err := f.db.CreateApp(context.Background(), f.app.OrganizationID, "Other app")
	if err != nil {
		t.Fatal(err)
	}
	status, body := f.request(t, "GET", "/api/v1/apps/"+otherApp.ID.String()+"/signing-key", f.owner, "", "")
	if status != 200 {
		t.Fatalf("other key %d %s", status, body)
	}
	var otherKey struct {
		Key struct {
			ID int `json:"id"`
		} `json:"signing_key"`
	}
	if err := json.Unmarshal(body, &otherKey); err != nil {
		t.Fatal(err)
	}
	status, body = f.multipart(t, fmt.Sprintf("/api/v1/apps/%s/releases/%d/artifacts", f.app.ID, f.release.ID), f.owner, map[string]string{"arch": "x64", "platform": "ios", "hash": strings.Repeat("a", 64), "size": "1", "filename": "App", "signing": fmt.Sprintf(`{"mode":"managed","key_id":%d}`, otherKey.Key.ID)})
	if status != 400 {
		t.Fatalf("foreign app key accepted: %d %s", status, body)
	}

	releasePath := fmt.Sprintf("/api/v1/apps/%s/releases/%d/artifacts", f.app.ID, f.release.ID)
	patchPath := fmt.Sprintf("/api/v1/apps/%s/patches/%d/artifacts", f.app.ID, f.patch.ID)
	for _, tc := range []struct {
		path, signing, signature, hash string
		status                         int
	}{
		{releasePath, `{"mode":"unsigned"}`, "", strings.Repeat("a", 64), 409},
		{patchPath, `{"mode":"unsigned"}`, "", strings.Repeat("a", 64), 400},
		{patchPath, "", "caller-signature", strings.Repeat("a", 64), 400},
		{patchPath, "", "", "not-a-sha256", 400},
	} {
		fields := map[string]string{"arch": "aarch64", "platform": "ios", "hash": tc.hash, "size": "1", "filename": "App"}
		if tc.path == releasePath {
			fields["arch"] = "xcarchive"
		}
		if tc.signing != "" {
			fields["signing"] = tc.signing
		}
		if tc.signature != "" {
			fields["hash_signature"] = tc.signature
		}
		status, data := f.multipart(t, tc.path, f.owner, fields)
		if status != tc.status {
			t.Fatalf("policy change %d want %d %s", status, tc.status, data)
		}
	}
	f.configure(t, nil, PatchDeliveryConfig{})
	status, data := f.multipart(t, patchPath, f.owner, map[string]string{"arch": "aarch64", "platform": "ios", "hash": strings.Repeat("a", 64), "size": "1"})
	if status != 503 {
		t.Fatalf("managed signing downgraded without master key: %d %s", status, data)
	}
}
func TestConcurrentReleaseRegistrationCannotSwitchSigningPolicyHTTP(t *testing.T) {
	f := newAPIFixture(t)
	f.configure(t, testSigningMasterKey, PatchDeliveryConfig{})
	id, _, _ := f.signingKey(t)
	path := fmt.Sprintf("/api/v1/apps/%s/releases/%d/artifacts", f.app.ID, f.release.ID)
	start := make(chan struct{})
	type result struct {
		status int
		err    error
	}
	results := make(chan result, 2)
	for _, policy := range []string{fmt.Sprintf(`{"mode":"managed","key_id":%d}`, id), `{"mode":"unsigned"}`} {
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		for key, value := range map[string]string{"arch": "xcarchive", "platform": "ios", "hash": strings.Repeat("a", 64), "size": "1", "filename": "App", "signing": policy} {
			if err := writer.WriteField(key, value); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequest(http.MethodPost, f.server.URL+path, bytes.NewReader(body.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", writer.FormDataContentType())
		request.Header.Set("Authorization", "Bearer "+f.owner)
		go func(request *http.Request) {
			<-start
			response, err := f.server.Client().Do(request)
			if err != nil {
				results <- result{err: err}
				return
			}
			response.Body.Close()
			results <- result{status: response.StatusCode}
		}(request)
	}
	close(start)
	first, second := <-results, <-results
	if first.err != nil || second.err != nil {
		t.Fatalf("concurrent requests failed: %v %v", first.err, second.err)
	}
	if !((first.status == 201 && second.status == 409) || (first.status == 409 && second.status == 201)) {
		t.Fatalf("concurrent signing policies were not serialized: %d %d", first.status, second.status)
	}
}

func TestManagedSigningHTTPResolvesRealCLICompositeBaselineShapes(t *testing.T) {
	cases := []struct {
		platform, primary, cpu string
		extra                  []string
	}{
		{"ios", "xcarchive", "aarch64", []string{"runner", "ios_supplement"}},
		{"ios", "xcframework", "aarch64", []string{"ios_supplement"}},
		{"ios", "runner", "aarch64", nil},
		{"macos", "app", "aarch64", []string{"macos_supplement"}},
		{"linux", "bundle", "x86_64", []string{"linux_supplement"}},
		{"windows", "win_archive", "x86_64", []string{"windows_supplement"}},
		{"android", "aarch64", "aarch64", []string{"aab", "android_supplement"}},
	}
	for _, tc := range cases {
		t.Run(tc.platform+"/"+tc.primary, func(t *testing.T) {
			f := newAPIFixture(t)
			f.configure(t, testSigningMasterKey, PatchDeliveryConfig{})
			keyID, _, key := f.signingKey(t)
			signing := fmt.Sprintf(`{"mode":"managed","key_id":%d}`, keyID)
			path := fmt.Sprintf("/api/v1/apps/%s/releases/%d/artifacts", f.app.ID, f.release.ID)
			for _, arch := range append([]string{tc.primary}, tc.extra...) {
				status, data := f.multipart(t, path, f.owner, map[string]string{"arch": arch, "platform": tc.platform, "hash": strings.Repeat("1", 64), "size": "1", "filename": arch, "signing": signing})
				if status != 201 {
					t.Fatalf("register %s: %d %s", arch, status, data)
				}
			}
			status, data := f.multipart(t, fmt.Sprintf("/api/v1/apps/%s/patches/%d/artifacts", f.app.ID, f.patch.ID), f.owner, map[string]string{"arch": tc.cpu, "platform": tc.platform, "hash": strings.Repeat("b", 64), "size": "1"})
			if status != 201 {
				t.Fatalf("device arch mapping: %d %s", status, data)
			}
			artifacts, err := f.db.GetPatchArtifacts(context.Background(), f.patch.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(artifacts) != 1 || artifacts[0].HashSignature == nil {
				t.Fatal("mapped managed patch is unsigned")
			}
			verifyRSASignature(t, key, []byte(strings.Repeat("b", 64)), *artifacts[0].HashSignature)
			status, data = f.request(t, "GET", fmt.Sprintf("/api/v1/apps/%s/releases", f.app.ID), f.owner, "", "")
			if status != 200 {
				t.Fatalf("release listing %d %s", status, data)
			}
			var listing struct {
				Releases []models.Release `json:"releases"`
			}
			if err := json.Unmarshal(data, &listing); err != nil {
				t.Fatal(err)
			}
			details := listing.Releases[0].Platforms[tc.platform]
			if details.Status != "draft" || details.SigningMode == nil || *details.SigningMode != "managed" {
				t.Fatalf("wrong platform details: %s", data)
			}
			request := models.PatchCheckRequest{AppID: f.app.ID.String(), ReleaseVersion: f.release.Version, Platform: tc.platform, Arch: tc.cpu, Channel: "stable", Nonce: uuid.NewString()}
			encoded, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			status, data = f.request(t, "POST", "/api/v1/patches/check", "", "application/json", string(encoded))
			var check models.PatchCheckResponse
			if err := json.Unmarshal(data, &check); err != nil {
				t.Fatal(err)
			}
			if status != 200 || check.Authentication == nil {
				t.Fatalf("mapped managed check is unsigned: %d %s", status, data)
			}
			payload, err := base64.StdEncoding.DecodeString(check.Authentication.Payload)
			if err != nil {
				t.Fatal(err)
			}
			verifyRSASignature(t, key, payload, check.Authentication.Signature)
		})
	}
}

func TestCompositeReleaseSigningPolicyRejectsMismatchedContainersAndSupplementsHTTP(t *testing.T) {
	f := newAPIFixture(t)
	f.configure(t, testSigningMasterKey, PatchDeliveryConfig{})
	keyID, _, _ := f.signingKey(t)
	f.registerBaseline(t, fmt.Sprintf(`{"mode":"managed","key_id":%d}`, keyID))
	path := fmt.Sprintf("/api/v1/apps/%s/releases/%d/artifacts", f.app.ID, f.release.ID)
	for _, arch := range []string{"runner", "ios_supplement"} {
		status, data := f.multipart(t, path, f.owner, map[string]string{"arch": arch, "platform": "ios", "hash": strings.Repeat("a", 64), "size": "1", "filename": arch, "signing": `{"mode":"unsigned"}`})
		if status != 409 {
			t.Fatalf("conflicting composite signing policy accepted: %d %s", status, data)
		}
	}
}

// Enable against an isolated, migrated database to validate the PostgreSQL path.
func TestManagedSigningPostgresHTTP(t *testing.T) {
	dsn := os.Getenv("SHOREBIRD_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set SHOREBIRD_TEST_POSTGRES_DSN to an isolated migrated PostgreSQL database")
	}
	store, err := db.NewPostgresStore(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	f := newAPIFixtureForStore(t, store, "")
	f.configure(t, testSigningMasterKey, PatchDeliveryConfig{})
	id, _, key := f.signingKey(t)
	f.registerBaseline(t, fmt.Sprintf(`{"mode":"managed","key_id":%d}`, id))
	hash := strings.Repeat("a", 64)
	f.registerManagedPatch(t, hash)
	artifacts, err := store.GetPatchArtifacts(context.Background(), f.patch.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts) != 1 || artifacts[0].HashSignature == nil {
		t.Fatal("PostgreSQL managed signature missing")
	}
	verifyRSASignature(t, key, []byte(hash), *artifacts[0].HashSignature)
	status, data := f.multipart(t, fmt.Sprintf("/api/v1/apps/%s/releases/%d/artifacts", f.app.ID, f.release.ID), f.owner, map[string]string{"arch": "runner", "platform": "ios", "hash": hash, "size": "1", "filename": "runner", "signing": `{"mode":"unsigned"}`})
	if status != 409 {
		t.Fatalf("PostgreSQL signing policy changed: %d %s", status, data)
	}
}

func TestLegacyAndExplicitReleaseSigningPoliciesHTTP(t *testing.T) {
	for _, tc := range []struct {
		mode, signature string
		want            int
	}{{"", "", 201}, {"customer", "", 400}, {"customer", "c2lnbmF0dXJl", 201}, {"unsigned", "", 201}, {"unsigned", "c2lnbmF0dXJl", 400}} {
		t.Run(tc.mode+tc.signature, func(t *testing.T) {
			f := newAPIFixture(t)
			signing := ""
			if tc.mode != "" {
				signing = `{"mode":"` + tc.mode + `"}`
			}
			f.registerBaseline(t, signing)
			fields := map[string]string{"arch": "aarch64", "platform": "ios", "hash": strings.Repeat("a", 64), "size": "1"}
			if tc.signature != "" {
				fields["hash_signature"] = tc.signature
			}
			status, data := f.multipart(t, fmt.Sprintf("/api/v1/apps/%s/patches/%d/artifacts", f.app.ID, f.patch.ID), f.owner, fields)
			if status != tc.want {
				t.Fatalf("signing policy %d want %d %s", status, tc.want, data)
			}
		})
	}
}
func TestRequiredEncryptionHTTPRejectsMissingCapabilitiesAndClientIdentity(t *testing.T) {
	f := newAPIFixture(t)
	f.configure(t, nil, PatchDeliveryConfig{EncryptionMode: PatchDeliveryEncryptionPerDeviceAESGCM, AESSecret: []byte("provisioned-server-secret")})
	for _, tc := range []struct{ extra, code string }{{``, "encrypted_patch_capability_required"}, {`,"accept_encrypted_patch":true`, "encrypted_patch_client_id_required"}, {`,"accept_encrypted_patch":true,"client_id":" "`, "encrypted_patch_client_id_required"}} {
		status, data := f.request(t, "POST", "/api/v1/patches/check", "", "application/json", fmt.Sprintf(`{"app_id":"%s"%s}`, f.app.ID, tc.extra))
		if status != 400 || !bytes.Contains(data, []byte(tc.code)) || bytes.Contains(data, []byte("download_url")) {
			t.Fatalf("plaintext downgrade %d %s", status, data)
		}
	}
	for _, mode := range []string{PatchDeliveryEncryptionPerDeviceAESGCM, "unknown"} {
		f.configure(t, nil, PatchDeliveryConfig{EncryptionMode: mode})
		status, data := f.request(t, "POST", "/api/v1/patches/check", "", "application/json", fmt.Sprintf(`{"app_id":"%s","accept_encrypted_patch":true,"client_id":"device-1"}`, f.app.ID))
		if status != 503 || !bytes.Contains(data, []byte("encrypted_patch_delivery_unavailable")) {
			t.Fatalf("invalid encryption config %d %s", status, data)
		}
	}

}
func TestAuthenticatedPatchCheckHTTPCoversDeliveryAndRollbackWithNonce(t *testing.T) {
	f := newAPIFixture(t)
	f.configure(t, testSigningMasterKey, PatchDeliveryConfig{})
	id, pubPEM, pub := f.signingKey(t)
	f.registerBaseline(t, fmt.Sprintf(`{"mode":"managed","key_id":%d}`, id))
	hash := strings.Repeat("b", 64)
	artifact := f.registerManagedPatch(t, hash)
	// Upload transport bytes through the actual signed storage upload HTTP route.
	upload, err := url.Parse(artifact.URL)
	if err != nil {
		t.Fatal(err)
	}
	status, data := f.request(t, "POST", upload.RequestURI(), "", "application/octet-stream", "patch")
	if status != 200 {
		t.Fatalf("upload %d %s", status, data)
	}
	channel, err := f.db.CreateChannel(context.Background(), f.app.ID, "stable")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.PromotePatch(context.Background(), f.patch.ID, channel.ID); err != nil {
		t.Fatal(err)
	}
	nonce := uuid.NewString()
	request := models.PatchCheckRequest{AppID: f.app.ID.String(), ReleaseVersion: f.release.Version, Platform: "ios", Arch: "aarch64", Channel: "stable", Nonce: nonce}
	check := func() (models.PatchCheckResponse, []byte, signedPatchCheckPayload) {
		body, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		status, data := f.request(t, "POST", "/api/v1/patches/check", "", "application/json", string(body))
		if status != 200 {
			t.Fatalf("patch check %d %s", status, data)
		}
		var response models.PatchCheckResponse
		if err := json.Unmarshal(data, &response); err != nil {
			t.Fatal(err)
		}
		if response.Authentication == nil {
			t.Fatalf("managed response missing authentication: %s", data)
		}
		payload, err := base64.StdEncoding.DecodeString(response.Authentication.Payload)
		if err != nil {
			t.Fatal(err)
		}
		verifyRSASignature(t, pub, payload, response.Authentication.Signature)
		var authenticated signedPatchCheckPayload
		if err := json.Unmarshal(payload, &authenticated); err != nil {
			t.Fatal(err)
		}
		if authenticated.Version != 1 || authenticated.Nonce != request.Nonce || authenticated.AppID != request.AppID || authenticated.ReleaseVersion != request.ReleaseVersion || authenticated.Platform != request.Platform || authenticated.Arch != request.Arch || authenticated.Channel != request.Channel {
			t.Fatalf("signed context mismatch: %s", payload)
		}
		return response, payload, authenticated
	}
	response, payload, signed := check()
	if !response.PatchAvailable || response.Patch == nil || signed.Patch == nil || signed.Patch.Hash != hash || signed.Patch.HashSignature == nil || *signed.Patch.HashSignature != *response.Patch.HashSignature || signed.Patch.DownloadURL != response.Patch.DownloadURL {
		t.Fatalf("signed offer mismatch: %s", payload)
	}
	verifyRSASignature(t, pub, []byte(hash), *response.Patch.HashSignature)
	if path := os.Getenv("SHOREBIRD_RESPONSE_FIXTURE"); path != "" {
		fixture := map[string]interface{}{"public_key_pem": pubPEM, "request": request, "response": response}
		serialized, err := json.MarshalIndent(fixture, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, serialized, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Client verifies auth before consuming this URL; test the storage download itself too.
	download, err := url.Parse(response.Patch.DownloadURL)
	if err != nil {
		t.Fatal(err)
	}
	status, data = f.request(t, "GET", download.RequestURI(), "", "", "")
	if status != 200 || string(data) != "patch" {
		t.Fatalf("download %d %s", status, data)
	}
	rollbackPath := fmt.Sprintf("/api/v1/apps/%s/releases/%d/patches/%d/rollback", f.app.ID, f.release.ID, f.patch.ID)
	status, data = f.request(t, "POST", rollbackPath, f.owner, "", "")
	if status != 204 {
		t.Fatalf("rollback %d %s", status, data)
	}
	request.Nonce = uuid.NewString()
	response, payload, signed = check()
	if response.PatchAvailable || signed.Patch != nil || len(signed.RolledBackPatchNumbers) != 1 || signed.RolledBackPatchNumbers[0] != 1 {
		t.Fatalf("rollback not authenticated: %s", payload)
	}
	rollforwardPath := strings.TrimSuffix(rollbackPath, "rollback") + "rollforward"
	status, data = f.request(t, "POST", rollforwardPath, f.owner, "", "")
	if status != 204 {
		t.Fatalf("rollforward %d %s", status, data)
	}
	current := 1
	request.CurrentPatchNumber = &current
	request.Nonce = uuid.NewString()
	response, payload, signed = check()
	if response.PatchAvailable || signed.Patch != nil || signed.RolledBackPatchNumbers == nil || len(signed.RolledBackPatchNumbers) != 0 {
		t.Fatalf("no-update not authenticated with [] rollback: %s", payload)
	}

	// A no-channel/no-update result is authenticated as well.
	request.Channel = "missing"
	request.Nonce = uuid.NewString()
	_, payload, signed = check()
	if signed.PatchAvailable || signed.Channel != "missing" {
		t.Fatalf("no-update context mismatch: %s", payload)
	}
}
