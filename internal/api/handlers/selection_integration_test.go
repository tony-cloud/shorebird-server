package handlers

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/klauspost/compress/zstd"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/shorebird-server/internal/db"
	"github.com/shorebird-server/internal/models"
	"github.com/shorebird-server/internal/selection"
)

type v2Fixture struct {
	*apiFixture
	path      string
	scopeBody map[string]any
	public    *rsa.PublicKey
}

func setupV2(t *testing.T, f *apiFixture) *v2Fixture {
	return setupV2Profile(t, f, "interpreter-structural")
}
func setupV2Profile(t *testing.T, f *apiFixture, profile string) *v2Fixture {
	t.Helper()
	f.configure(t, testSigningMasterKey, PatchDeliveryConfig{})
	path := "/api/v1/apps/" + f.app.ID.String() + "/releases"
	status, data := f.request(t, "POST", path, f.owner, "application/json", `{"version":"2.0.0+1","flutter_revision":"rev","selection_protocol":2}`)
	if status != 201 {
		t.Fatalf("create %d %s", status, data)
	}
	var created models.CreateReleaseResponse
	if e := json.Unmarshal(data, &created); e != nil {
		t.Fatal(e)
	}
	if created.Release.SelectionProtocol != 2 {
		t.Fatal("protocol absent")
	}
	var e error
	f.release, e = f.db.GetReleaseByID(context.Background(), created.Release.ID)
	if e != nil {
		t.Fatal(e)
	}
	keyID, _, public := f.signingKey(t)
	f.registerBaseline(t, fmt.Sprintf(`{"mode":"managed","key_id":%d}`, keyID))
	status, data = f.multipart(t, fmt.Sprintf("%s/%d/artifacts", path, f.release.ID), f.owner, map[string]string{"arch": "ios_supplement", "platform": "ios", "hash": strings.Repeat("2", 64), "size": "8", "filename": "base.dbc", "signing": fmt.Sprintf(`{"mode":"managed","key_id":%d}`, keyID)})
	if status != 201 {
		t.Fatalf("supplement %d %s", status, data)
	}
	artifacts, e := f.db.GetReleaseArtifacts(context.Background(), f.release.ID, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	var primary, supplement int
	for _, a := range artifacts {
		if a.Arch == "xcarchive" {
			primary = a.ID
		} else {
			supplement = a.ID
		}
	}
	v := &v2Fixture{f, fmt.Sprintf("%s/%d", path, f.release.ID), map[string]any{"base_artifact_hash": strings.Repeat("a", 64), "host_abi_hash": nil, "runtime_profile": profile, "release_artifact_id": primary, "supplement_artifact_id": supplement}, public}
	v.call(t, "PUT", "/selection-scopes/ios/aarch64", f.owner, v.scopeBody, 201)
	v.call(t, "PATCH", "", f.owner, map[string]any{"platform": "ios", "status": "active", "selection_arches": []string{"aarch64"}}, 204)
	v.mapVariant(t, "free", 0, nil)
	return v
}
func (v *v2Fixture) call(t *testing.T, method, suffix, token string, body any, want int) []byte {
	t.Helper()
	encoded, _ := json.Marshal(body)
	status, data := v.request(t, method, v.path+suffix, token, "application/json", string(encoded))
	if status != want {
		t.Fatalf("%s %s got %d want %d: %s", method, suffix, status, want, data)
	}
	return data
}
func (v *v2Fixture) mapVariant(t *testing.T, variant string, number int, expires *time.Time) {
	t.Helper()
	target := selection.Target{Kind: "base", Encryption: "none"}
	if number > 0 {
		p, e := v.db.CreatePatch(context.Background(), v.release.ID, number, nil)
		if e != nil {
			t.Fatal(e)
		}
		keyID, _, _ := v.signingKey(t)
		key, e := v.db.GetSigningKeyByID(context.Background(), keyID)
		if e != nil {
			t.Fatal(e)
		}
		payload := []byte(fmt.Sprintf(`{"format":"open-aot-vmcode-encrypted-v1","metadata":{"app_id":"%s","flavor_id":"%s","license_type":"%s","base_snapshot_hash":"%s"},"encryption":{"algorithm":"AES-256-GCM","key_id":"key-%s"},"encrypted_payload_base64":"dGVzdA=="}`, v.app.ID, variant, variant, strings.Repeat("a", 64), variant))
		transport := interpreterTestTransport(t, payload)
		hash := sha256Hex(payload)
		signer := SigningHandler{MasterKey: testSigningMasterKey}
		signature, e := signer.signMessage(key, []byte(hash))
		if e != nil {
			t.Fatal(e)
		}
		storageKey := fmt.Sprintf("v2/%s/%d", v.app.ID, number)
		if e = v.objects.UploadObject(context.Background(), storageKey, bytes.NewReader(transport), int64(len(transport)), "application/octet-stream", false); e != nil {
			t.Fatal(e)
		}
		if _, e = v.db.CreatePatchArtifact(context.Background(), p.ID, "aarch64", "ios", hash, storageKey, int64(len(transport)), &signature, nil, expires); e != nil {
			t.Fatal(e)
		}
		num, keyIDString := strconv.Itoa(number), "key-"+variant
		target = selection.Target{Kind: "patch", PatchNumber: &num, ArtifactHash: &hash, Encryption: "artifact-aes-256-gcm", ArtifactKeyID: &keyIDString}
		if v.scopeBody["runtime_profile"] == "native-aot" {
			target.Encryption = "transport-aes-256-gcm"
			target.ArtifactKeyID = nil
		}
	}
	v.call(t, "PUT", "/variants/"+variant, v.owner, selection.Mapping{Platform: "ios", Arch: "aarch64", Channel: "stable", LicenseType: variant, Target: target}, 200)
}
func (v *v2Fixture) assignBody(variant, epoch string) map[string]any {
	return map[string]any{"client_id": "installation", "platform": "ios", "arch": "aarch64", "channel": "stable", "variant_id": variant, "entitlement_revision": "backend-policy-7", "not_before": "0", "offline_valid_until": nil, "expected_epoch": epoch, "idempotency_key": uuid.NewString()}
}
func (v *v2Fixture) assign(t *testing.T, variant, epoch string) selection.Result {
	t.Helper()
	data := v.call(t, "POST", "/selections", v.owner, v.assignBody(variant, epoch), 200)
	var result selection.Result
	if e := json.Unmarshal(data, &result); e != nil {
		t.Fatal(e)
	}
	return result
}
func (v *v2Fixture) checkBody(epoch string, digest *string) map[string]any {
	return map[string]any{"selection_protocol": 2, "app_id": v.app.ID.String(), "release_version": v.release.Version, "platform": "ios", "arch": "aarch64", "client_id": "installation", "nonce": uuid.NewString(), "base_artifact_hash": strings.Repeat("a", 64), "host_abi_hash": nil, "runtime_profile": v.scopeBody["runtime_profile"], "accepted_selection_epoch": epoch, "accepted_selection_digest": digest}
}
func (v *v2Fixture) check(t *testing.T, body map[string]any, want int) selectionResponse {
	t.Helper()
	encoded, _ := json.Marshal(body)
	status, data := v.request(t, "POST", "/api/v1/patches/check", "", "application/json", string(encoded))
	if status != want {
		t.Fatalf("check %d want %d %s", status, want, data)
	}
	var response selectionResponse
	if want != 200 {
		return response
	}
	if e := json.Unmarshal(data, &response); e != nil {
		t.Fatal(e)
	}
	payload, e := base64.StdEncoding.DecodeString(response.Authentication.Payload)
	if e != nil {
		t.Fatal(e)
	}
	verifyRSASignature(t, v.public, payload, response.Authentication.Signature)
	var signed selectionPayload
	if e := json.Unmarshal(payload, &signed); e != nil {
		t.Fatal(e)
	}
	if signed.Request.Nonce != body["nonce"] || signed.Request.Channel != "stable" {
		t.Fatal("request nonce or default channel not bound")
	}
	a, _ := json.Marshal(signed.Selection)
	b, _ := json.Marshal(response.Selection)
	if !bytes.Equal(a, b) || signed.SelectionDigest != response.SelectionDigest {
		t.Fatal("outer selection not signed")
	}
	digest, e := response.Selection.Digest()
	if e != nil || digest != response.SelectionDigest {
		t.Fatal("digest mismatch")
	}
	return response
}

func testVariantSelectionFlow(t *testing.T, f *apiFixture) {
	v := setupV2(t, f)
	v.mapVariant(t, "pro", 2, nil)
	v.mapVariant(t, "enterprise", 3, nil)
	testVariantStorageNamespace(t, v)
	first := v.check(t, v.checkBody("0", nil), 200)
	if first.Selection.Epoch != "1" || first.Selection.Target.Kind != "base" || first.Delivery != nil {
		t.Fatal("public bootstrap was not explicit free base")
	}
	for _, tc := range []struct{ variant, old, epoch, number string }{{"enterprise", "1", "2", "3"}, {"pro", "2", "3", "2"}, {"free", "3", "4", ""}, {"enterprise", "4", "5", "3"}, {"pro", "5", "6", "2"}} {
		result := v.assign(t, tc.variant, tc.old)
		if result.Selection.Epoch != tc.epoch {
			t.Fatal("epoch not independent of patch")
		}
		response := v.check(t, v.checkBody(result.Selection.Epoch, &result.SelectionDigest), 200)
		if tc.number != "" && (response.Delivery == nil || response.Delivery.Number != tc.number || response.Delivery.Encryption != nil) {
			t.Fatal("wrong interpreter delivery")
		}
	}
	// Mapping changes do not mutate a committed grant; nonce refresh preserves digest.
	current := v.check(t, v.checkBody("0", nil), 200)
	refresh := v.check(t, v.checkBody(current.Selection.Epoch, &current.SelectionDigest), 200)
	if refresh.SelectionDigest != current.SelectionDigest {
		t.Fatal("refresh allocated grant")
	}
	// A rollback followed immediately by rollforward must preserve durable replacement.
	if _, e := v.db.SetPatchRolledBack(context.Background(), v.release.ID, 2, true); e != nil {
		t.Fatal(e)
	}
	if _, e := v.db.SetPatchRolledBack(context.Background(), v.release.ID, 2, false); e != nil {
		t.Fatal(e)
	}
	after := v.check(t, v.checkBody("0", nil), 200)
	if after.Selection.Epoch != "7" || after.Selection.Target.Kind != "base" || after.Selection.EntitlementRevision != "server-free-7" {
		t.Fatalf("revocation resurrected: %+v", after.Selection)
	}
	// Explicit assignment can select eligible content again at a new epoch.
	paid := v.assign(t, "pro", "7")
	if paid.Selection.Epoch != "8" {
		t.Fatal("rollforward did not allow explicit assignment")
	}
	// Two authenticated concurrent CAS mutations admit only one winner.
	left, right := v.assignBody("free", "8"), v.assignBody("enterprise", "8")
	statuses := make(chan int, 2)
	var wg sync.WaitGroup
	for _, body := range []map[string]any{left, right} {
		wg.Add(1)
		go func(body map[string]any) {
			defer wg.Done()
			b, _ := json.Marshal(body)
			status, _ := v.request(t, "POST", v.path+"/selections", v.owner, "application/json", string(b))
			statuses <- status
		}(body)
	}
	wg.Wait()
	close(statuses)
	counts := map[int]int{}
	for s := range statuses {
		counts[s]++
	}
	if counts[200] != 1 || counts[409] != 1 {
		t.Fatalf("CAS race %+v", counts)
	}
	// Historical idempotency retries remain operation records only.
	operation := v.assignBody("free", "9")
	data := v.call(t, "POST", "/selections", v.owner, operation, 200)
	retry := v.call(t, "POST", "/selections", v.owner, operation, 200)
	if !bytes.Equal(data, retry) {
		t.Fatal("idempotency changed result")
	}
	operation["variant_id"] = "pro"
	v.call(t, "POST", "/selections", v.owner, operation, 409)
	for _, token := range []string{"", v.outsider, v.reader} {
		want := 403
		if token == "" {
			want = 401
		}
		v.call(t, "POST", "/selections", token, v.assignBody("pro", "10"), want)
	}
	for _, mutation := range []func(map[string]any){func(b map[string]any) { b["base_artifact_hash"] = strings.Repeat("b", 64) }, func(b map[string]any) {
		b["accepted_selection_epoch"] = "999"
		b["accepted_selection_digest"] = strings.Repeat("f", 64)
	}, func(b map[string]any) { b["channel"] = "beta" }} {
		body := v.checkBody("0", nil)
		mutation(body)
		v.check(t, body, 409)
	}
	// Epoch/digest conflicts and missing nonce do not return device authentication.
	body := v.checkBody("10", func() *string { s := strings.Repeat("f", 64); return &s }())
	v.check(t, body, 409)
	body = v.checkBody("0", nil)
	delete(body, "nonce")
	v.check(t, body, 400)
	// Scope write-once retries are allowed after publication; changes are not.
	v.call(t, "PUT", "/selection-scopes/ios/aarch64", v.owner, v.scopeBody, 200)
	changed := map[string]any{}
	for k, val := range v.scopeBody {
		changed[k] = val
	}
	changed["base_artifact_hash"] = strings.Repeat("c", 64)
	v.call(t, "PUT", "/selection-scopes/ios/aarch64", v.owner, changed, 409)
	v.call(t, "PUT", "/selection-scopes/ios/x86_64", v.owner, v.scopeBody, 409)
	v.call(t, "PATCH", "", v.owner, map[string]any{"platform": "ios", "status": "active"}, 400)
	v.call(t, "PATCH", "", v.owner, map[string]any{"platform": "ios", "status": "draft"}, 409)
	v.call(t, "PATCH", "", v.owner, map[string]any{"platform": "ios", "status": "inactive", "metadata": map[string]any{"base_artifact_hash": "spoof"}}, 400)
	v.call(t, "PATCH", "", v.owner, map[string]any{"platform": "ios", "status": "inactive"}, 204)
	v.check(t, v.checkBody("0", nil), 409)
	v.call(t, "PATCH", "", v.owner, map[string]any{"platform": "ios", "status": "active", "selection_arches": []string{"aarch64"}}, 204)
	// Published v2 artifacts and immutable patch content cannot allocate overwrite grants.
	status, _ := v.multipart(t, v.path+"/artifacts", v.owner, map[string]string{"arch": "runner", "platform": "ios", "hash": strings.Repeat("d", 64), "size": "1", "filename": "other", "signing": fmt.Sprintf(`{"mode":"managed","key_id":%d}`, func() int { id, _, _ := v.signingKey(t); return id }())})
	if status != 409 {
		t.Fatalf("published upload accepted %d", status)
	}
	v.call(t, "DELETE", "", v.owner, nil, 204)
	status, data = v.request(t, "POST", "/api/v1/apps/"+v.app.ID.String()+"/releases", v.owner, "application/json", `{"version":"2.0.0+1","selection_protocol":1}`)
	if status != 409 {
		t.Fatalf("release namespace reused %d %s", status, data)
	}
}
func TestVariantSelectionV2SQLiteHTTP(t *testing.T) { testVariantSelectionFlow(t, newAPIFixture(t)) }
func TestVariantSelectionV2PostgresHTTP(t *testing.T) {
	dsn := os.Getenv("SHOREBIRD_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set SHOREBIRD_TEST_POSTGRES_DSN for isolated PostgreSQL validation")
	}
	ctx := context.Background()
	conn, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close(ctx)
	schema := "selection_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, e = conn.Exec(ctx, "CREATE SCHEMA "+schema); e != nil {
		t.Fatal(e)
	}
	defer conn.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
	if _, e = conn.Exec(ctx, "SET search_path TO "+schema); e != nil {
		t.Fatal(e)
	}
	files, e := filepath.Glob("../../db/migrations/*.sql")
	if e != nil {
		t.Fatal(e)
	}
	for _, file := range files {
		data, e := os.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		up := strings.Split(string(data), "-- +goose Down")[0]
		if _, e = conn.Exec(ctx, up); e != nil {
			t.Fatalf("migration %s: %v", file, e)
		}
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	store, e := db.NewPostgresStore(ctx, dsn+sep+"search_path="+schema)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	testVariantSelectionFlow(t, newAPIFixtureForStore(t, store, ""))
}

func TestVariantSelectionV2NativeEncryptionAndLeaseCaps(t *testing.T) {
	t.Run("native encryption", func(t *testing.T) {
		v := setupV2Profile(t, newAPIFixture(t), "native-aot")
		v.mapVariant(t, "pro", 2, nil)
		result := v.assign(t, "pro", "0")
		v.check(t, v.checkBody("0", nil), 409)
		v.configure(t, testSigningMasterKey, PatchDeliveryConfig{EncryptionMode: PatchDeliveryEncryptionPerDeviceAESGCM, AESSecret: []byte("native-selection-secret")})
		request := v.checkBody(result.Selection.Epoch, &result.SelectionDigest)
		request["accept_encrypted_patch"] = true
		response := v.check(t, request, 200)
		if response.Delivery == nil || response.Delivery.Encryption == nil || response.Delivery.Encryption.DeviceIDHash != selection.ClientHash("installation") {
			t.Fatal("native transport not bound to installation")
		}
		aad, e := base64.RawURLEncoding.DecodeString(response.Delivery.Encryption.AAD)
		if e != nil || !strings.Contains(string(aad), "platform=ios\narch=aarch64\n") {
			t.Fatal("native transport missing immutable request binding")
		}
	})
	t.Run("finite content expiry", func(t *testing.T) {
		v := setupV2(t, newAPIFixture(t))
		expires := time.Now().UTC().Add(time.Hour)
		v.mapVariant(t, "pro", 2, &expires)
		request := v.assignBody("pro", "0")
		failure := v.call(t, "POST", "/selections", v.owner, request, 409)
		if !bytes.Contains(failure, []byte(`"code":"selection_exceeds_content_expiry"`)) {
			t.Fatalf("wrong content expiry code: %s", failure)
		}
		request["offline_valid_until"] = strconv.FormatInt(expires.Unix()+1, 10)
		v.call(t, "POST", "/selections", v.owner, request, 409)
		request["offline_valid_until"] = strconv.FormatInt(expires.Unix(), 10)
		v.call(t, "POST", "/selections", v.owner, request, 200)
		// Equality with a grant expiry resolves a newer durable free selection.
		request = v.assignBody("pro", "1")
		request["offline_valid_until"] = strconv.FormatInt(time.Now().UTC().Unix(), 10)
		v.call(t, "POST", "/selections", v.owner, request, 200)
		response := v.check(t, v.checkBody("0", nil), 200)
		if response.Selection.Epoch != "3" || response.Selection.Target.Kind != "base" {
			t.Fatal("expired grant did not allocate free base")
		}
	})
}
func TestVariantSelectionV2RegistrationGuards(t *testing.T) {
	f := newAPIFixture(t)
	v := setupV2(t, f)
	// Published bindings are readable with a read-only role, but cannot be mutated.
	v.call(t, "GET", "/selection-scopes", v.reader, nil, 200)
	v.call(t, "PUT", "/selection-scopes/ios/aarch64", v.reader, v.scopeBody, 403)
	v.call(t, "PUT", "/variants/free", v.reader, selection.Mapping{}, 403)
	for _, body := range []string{`{"version":"null-protocol","selection_protocol":null}`, `{"version":"unknown-protocol","selection_protocol":3}`, `{"version":"fraction-protocol","selection_protocol":2.0}`, `{"version":"dup-protocol","selection_protocol":1,"selection_protocol":2}`} {
		status, _ := v.request(t, "POST", "/api/v1/apps/"+v.app.ID.String()+"/releases", v.owner, "application/json", body)
		if status != 400 {
			t.Fatalf("invalid create accepted %d %s", status, body)
		}
	}
	// Legacy releases cannot be promoted by a public device opt-in or scope PUT.
	legacy, e := v.db.CreateRelease(context.Background(), v.app.ID, "legacy", "rev", nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	oldPath := v.path
	v.path = fmt.Sprintf("/api/v1/apps/%s/releases/%d", v.app.ID, legacy.ID)
	v.call(t, "PUT", "/selection-scopes/ios/aarch64", v.owner, v.scopeBody, 409)
	v.path = oldPath
	// Missing nullable fields, duplicates and unknown nested target keys fail closed.
	raw := `{"platform":"ios","arch":"aarch64","channel":"stable","license_type":"free","target":{"kind":"base","patch_number":null,"artifact_hash":null,"encryption":"none"}}`
	status, _ := v.request(t, "PUT", v.path+"/variants/free", v.owner, "application/json", raw)
	if status != 400 {
		t.Fatal("missing target nullable field accepted")
	}
	body := v.checkBody("0", nil)
	body["runtime_profile"] = "native-aot"
	v.check(t, body, 409)
	// Freeze persists independently of status; deactivation cannot reopen uploads.
	v.call(t, "PATCH", "", v.owner, map[string]any{"platform": "ios", "status": "inactive"}, 204)
	v.call(t, "PUT", "/selection-scopes/ios/x86_64", v.owner, v.scopeBody, 409)
}

func testVariantStorageNamespace(t *testing.T, v *v2Fixture) {
	t.Helper()
	ctx := context.Background()
	p, e := v.db.CreatePatch(ctx, v.release.ID, 99, nil)
	if e != nil {
		t.Fatal(e)
	}
	v.patch = p
	v.registerManagedPatch(t, strings.Repeat("d", 64))
	duplicateStatus, duplicateBody := v.multipart(t, fmt.Sprintf("/api/v1/apps/%s/patches/%d/artifacts", v.app.ID, p.ID), v.owner, map[string]string{"platform": "ios", "arch": "aarch64", "size": "1", "hash": strings.Repeat("e", 64)})
	if duplicateStatus != 409 {
		t.Fatalf("duplicate v2 content allocation returned %d: %s", duplicateStatus, duplicateBody)
	}
	legacy, e := v.db.CreateRelease(ctx, v.app.ID, strconv.Itoa(v.release.ID), "rev", nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	path := fmt.Sprintf("/api/v1/apps/%s/releases/%d/artifacts", v.app.ID, legacy.ID)
	fields := map[string]string{"platform": "patches", "arch": "99", "filename": "ios/aarch64/dlc.vmcode", "size": "1", "hash": strings.Repeat("e", 64)}
	status, data := v.multipart(t, path, v.owner, fields)
	if status != 409 {
		t.Fatalf("legacy allocation overwrote protected v2 patch: %d %s", status, data)
	}
	// Allocation in the other direction also rejects an already allocated legacy key.
	fields["arch"] = "100"
	status, data = v.multipart(t, path, v.owner, fields)
	if status != 201 {
		t.Fatalf("legacy allocation %d %s", status, data)
	}
	p, e = v.db.CreatePatch(ctx, v.release.ID, 100, nil)
	if e != nil {
		t.Fatal(e)
	}
	status, data = v.multipart(t, fmt.Sprintf("/api/v1/apps/%s/patches/%d/artifacts", v.app.ID, p.ID), v.owner, map[string]string{"platform": "ios", "arch": "aarch64", "size": "1", "hash": strings.Repeat("f", 64)})
	if status != 409 {
		t.Fatalf("v2 allocation overwrote legacy storage: %d %s", status, data)
	}
	// Distinct parent-release locks still serialize a colliding first allocation
	// through the global registry key, in both SQLite and PostgreSQL.
	p, e = v.db.CreatePatch(ctx, v.release.ID, 101, nil)
	if e != nil {
		t.Fatal(e)
	}
	statuses := make(chan int, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		status, _ := v.multipart(t, path, v.owner, map[string]string{"platform": "patches", "arch": "101", "filename": "ios/aarch64/dlc.vmcode", "size": "1", "hash": strings.Repeat("e", 64)})
		statuses <- status
	}()
	go func() {
		defer wg.Done()
		status, _ := v.multipart(t, fmt.Sprintf("/api/v1/apps/%s/patches/%d/artifacts", v.app.ID, p.ID), v.owner, map[string]string{"platform": "ios", "arch": "aarch64", "size": "1", "hash": strings.Repeat("f", 64)})
		statuses <- status
	}()
	wg.Wait()
	close(statuses)
	counts := map[int]int{}
	for status := range statuses {
		counts[status]++
	}
	if counts[201] != 1 || counts[409] != 1 {
		t.Fatalf("colliding allocation race: %+v", counts)
	}
}

// Set SHOREBIRD_TEST_PATCH_ENCODER to the pinned updater patch executable for
// producer/consumer integration. Standalone tests also exercise the exact same
// documented literal representation without requiring a sibling Rust checkout.
func interpreterTestTransport(t *testing.T, envelope []byte) []byte {
	t.Helper()
	if encoder := os.Getenv("SHOREBIRD_TEST_PATCH_ENCODER"); encoder != "" {
		dir := t.TempDir()
		base, newer, out := filepath.Join(dir, "empty"), filepath.Join(dir, "envelope.json"), filepath.Join(dir, "transport.patch")
		if e := os.WriteFile(base, nil, 0600); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(newer, envelope, 0600); e != nil {
			t.Fatal(e)
		}
		if output, e := exec.Command(encoder, base, newer, out).CombinedOutput(); e != nil {
			t.Fatalf("production patch encoder: %v %s", e, output)
		}
		data, e := os.ReadFile(out)
		if e != nil {
			t.Fatal(e)
		}
		return data
	}
	raw := append([]byte(nil), interpreterBipatchHeader...)
	raw = append(raw, 0)
	raw = binary.AppendUvarint(raw, uint64(len(envelope)))
	raw = append(raw, envelope...)
	raw = append(raw, 0)
	encoder, e := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if e != nil {
		t.Fatal(e)
	}
	defer encoder.Close()
	return encoder.EncodeAll(raw, nil)
}

func TestVariantSelectionV2RejectsRawEnvelopeTransport(t *testing.T) {
	v := setupV2(t, newAPIFixture(t))
	v.mapVariant(t, "pro", 2, nil)
	result := v.assign(t, "pro", "0")
	patch, e := v.db.GetPatchByReleaseNumber(context.Background(), v.release.ID, 2, "aarch64", "ios")
	if e != nil {
		t.Fatal(e)
	}
	reader, e := v.objects.GetObject(context.Background(), patch.StorageKey, false)
	if e != nil {
		t.Fatal(e)
	}
	transport, e := io.ReadAll(reader)
	reader.Close()
	if e != nil {
		t.Fatal(e)
	}
	envelope, e := reconstructInterpreterTransport(transport)
	if e != nil {
		t.Fatal(e)
	}
	if sha256Hex(envelope) != *result.Selection.Target.ArtifactHash || sha256Hex(transport) == *result.Selection.Target.ArtifactHash {
		t.Fatal("installed and transport hashes conflated")
	}
	// An external overwrite with reconstructed raw JSON must fail both mapping and
	// delivery, even though those bytes hash to the signed installed target.
	if e = v.objects.UploadObject(context.Background(), patch.StorageKey, bytes.NewReader(envelope), int64(len(envelope)), "application/json", false); e != nil {
		t.Fatal(e)
	}
	v.check(t, v.checkBody("0", nil), 409)
	v.call(t, "PUT", "/variants/pro", v.owner, selection.Mapping{Platform: "ios", Arch: "aarch64", Channel: "stable", LicenseType: "pro", Target: result.Selection.Target}, 409)
}
