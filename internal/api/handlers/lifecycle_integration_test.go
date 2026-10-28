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
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/shorebird-server/internal/auth"
	"github.com/shorebird-server/internal/db"
	"github.com/shorebird-server/internal/storage"
)

type apiFixture struct {
	db                      *db.SqliteStore
	server                  *httptest.Server
	auth                    *auth.Service
	app                     *db.AppRow
	release                 *db.ReleaseRow
	patch                   *db.PatchRow
	owner, outsider, reader string
	ownerID                 int
}

func newAPIFixture(t *testing.T) *apiFixture {
	t.Helper()
	store, err := db.NewSqliteStore(t.TempDir() + "/server.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	service := auth.NewService("integration-secret", time.Hour)
	f := &apiFixture{db: store, auth: service}
	ctx := context.Background()
	hash, err := auth.HashPassword("test-password")
	if err != nil {
		t.Fatal(err)
	}
	createUser := func(email string) (int, string) {
		id, err := store.CreateUser(ctx, email, email, hash)
		if err != nil {
			t.Fatal(err)
		}
		if err = store.MarkUserEmailVerified(ctx, id); err != nil {
			t.Fatal(err)
		}
		if err = store.SetUserAdmin(ctx, id, false); err != nil {
			t.Fatal(err)
		}
		token, err := service.GenerateToken(id, email)
		if err != nil {
			t.Fatal(err)
		}
		return id, token
	}
	var readerID int
	f.ownerID, f.owner = createUser("owner@example.test")
	_, f.outsider = createUser("outsider@example.test")
	readerID, f.reader = createUser("reader@example.test")
	orgID, err := store.CreateOrganization(ctx, "test", "team")
	if err != nil {
		t.Fatal(err)
	}
	if err = store.AddUserToOrganization(ctx, f.ownerID, orgID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err = store.AddUserToOrganization(ctx, readerID, orgID, "member"); err != nil {
		t.Fatal(err)
	}
	f.app, err = store.CreateApp(ctx, orgID, "Test app")
	if err != nil {
		t.Fatal(err)
	}
	f.release, err = store.CreateRelease(ctx, f.app.ID, "1.0.0+1", "flutter-rev", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.patch, err = store.CreatePatch(ctx, f.release.ID, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	objects, err := storage.NewLocalStore(t.TempDir(), "http://updates.test", "")
	if err != nil {
		t.Fatal(err)
	}
	f.server = httptest.NewServer(NewRouter(service, store, objects, nil, "", PatchDeliveryConfig{}))
	t.Cleanup(f.server.Close)
	return f
}
func (f *apiFixture) request(t *testing.T, method, path, token, contentType, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, f.server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := f.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, data
}
func TestGetAppHTTPAuthorizationAndSchema(t *testing.T) {
	f := newAPIFixture(t)
	path := "/api/v1/apps/" + f.app.ID.String()
	for _, tc := range []struct {
		name, path, token string
		status            int
	}{{"anonymous", path, "", 401}, {"owner", path, f.owner, 200}, {"member", path, f.reader, 200}, {"outsider", path, f.outsider, 403}, {"missing", "/api/v1/apps/" + uuid.NewString(), f.owner, 404}, {"invalid", "/api/v1/apps/invalid", f.owner, 400}} {
		t.Run(tc.name, func(t *testing.T) {
			status, body := f.request(t, "GET", tc.path, tc.token, "", "")
			if status != tc.status {
				t.Fatalf("status %d want %d: %s", status, tc.status, body)
			}
			if status == 200 {
				var app map[string]any
				if err := json.Unmarshal(body, &app); err != nil {
					t.Fatal(err)
				}
				if app["app_id"] != f.app.ID.String() || app["display_name"] != "Test app" || app["organization_id"] == nil || app["created_at"] == nil || app["updated_at"] == nil {
					t.Fatalf("bad AppMetadata: %s", body)
				}
			}
		})
	}
}
func TestPatchLifecycleHTTPIsScopedAndIdempotent(t *testing.T) {
	f := newAPIFixture(t)
	path := fmt.Sprintf("/api/v1/apps/%s/releases/%d/patches/%d/", f.app.ID, f.release.ID, f.patch.ID)
	channel, err := f.db.CreateChannel(context.Background(), f.app.ID, "stable")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.PromotePatch(context.Background(), f.patch.ID, channel.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.CreatePatchArtifact(context.Background(), f.patch.ID, "aarch64", "ios", "hash", "patch", 1, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		action, token string
		status        int
	}{{"rollback", "", 401}, {"rollback", f.outsider, 403}, {"rollback", f.reader, 403}, {"rollback", f.owner, 204}, {"rollback", f.owner, 304}, {"rollforward", f.owner, 204}, {"rollforward", f.owner, 304}} {
		status, body := f.request(t, "POST", path+tc.action, tc.token, "", "")
		if status != tc.status {
			t.Fatalf("%s: status %d want %d: %s", tc.action, status, tc.status, body)
		}
	}
	// The listing is consumed by the CLI before rollback and must use ReleasePatch's schema.
	listPath := fmt.Sprintf("/api/v1/apps/%s/releases/%d/patches", f.app.ID, f.release.ID)
	status, data := f.request(t, "GET", listPath, f.owner, "", "")
	if status != 200 {
		t.Fatalf("listing %d %s", status, data)
	}
	var listing struct {
		Patches []struct {
			Number     int              `json:"number"`
			Artifacts  []map[string]any `json:"artifacts"`
			RolledBack bool             `json:"is_rolled_back"`
		} `json:"patches"`
	}
	if err := json.Unmarshal(data, &listing); err != nil {
		t.Fatal(err)
	}
	if len(listing.Patches) != 1 || listing.Patches[0].Number != 1 || len(listing.Patches[0].Artifacts) != 1 || listing.Patches[0].RolledBack {
		t.Fatalf("bad ReleasePatch listing: %s", data)
	}
	status, data = f.request(t, "POST", path+"rollback", f.owner, "", "")
	if status != 204 {
		t.Fatalf("rollback %d %s", status, data)
	}
	status, data = f.request(t, "POST", "/api/v1/patches/check", "", "application/json", fmt.Sprintf(`{"app_id":"%s","release_version":"1.0.0+1","platform":"ios","arch":"aarch64","channel":"stable"}`, f.app.ID))
	if status != 200 || !bytes.Contains(data, []byte(`"patch_available":false`)) || !bytes.Contains(data, []byte(`"rolled_back_patch_numbers":[1]`)) {
		t.Fatalf("rolled-back artifact still offered: %d %s", status, data)
	}
	otherRelease, err := f.db.CreateRelease(context.Background(), f.app.ID, "2.0.0+1", "rev", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	wrongPath := fmt.Sprintf("/api/v1/apps/%s/releases/%d/patches/%d/rollback", f.app.ID, otherRelease.ID, f.patch.ID)
	status, body := f.request(t, "POST", wrongPath, f.owner, "", "")
	if status != 404 {
		t.Fatalf("cross-release: %d %s", status, body)
	}
	// A server admin using the legacy route must still match the path's app.
	if err := f.db.SetUserAdmin(context.Background(), f.ownerID, true); err != nil {
		t.Fatal(err)
	}
	status, body = f.request(t, "POST", "/api/v1/apps/"+uuid.NewString()+"/patches/rollback", f.owner, "application/json", fmt.Sprintf(`{"release_id":%d,"patch_number":1}`, f.release.ID))
	if status != 404 {
		t.Fatalf("legacy cross-app: %d %s", status, body)
	}
}
func TestOAuthRefreshHTTPRotatesOpaqueTokensAndRejectsReplay(t *testing.T) {
	f := newAPIFixture(t)
	globalCodeStore.mu.Lock()
	globalCodeStore.codes["integration-code"] = authCodeEntry{email: "owner@example.test", expiresAt: time.Now().Add(time.Minute)}
	globalCodeStore.mu.Unlock()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {"integration-code"}}
	status, body := f.request(t, "POST", "/auth/token", "", "application/x-www-form-urlencoded", form.Encode())
	if status != 200 {
		t.Fatalf("exchange %d %s", status, body)
	}
	var first oauthTokenResponse
	if err := json.Unmarshal(body, &first); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(first.RefreshToken, "sb_rt_") || first.ExpiresIn != 3600 {
		t.Fatalf("bad token response %s", body)
	}
	form = url.Values{"grant_type": {"refresh_token"}, "refresh_token": {first.RefreshToken}}
	status, body = f.request(t, "POST", "/auth/token", "", "application/x-www-form-urlencoded", form.Encode())
	if status != 200 {
		t.Fatalf("refresh %d %s", status, body)
	}
	var second oauthTokenResponse
	if err := json.Unmarshal(body, &second); err != nil {
		t.Fatal(err)
	}
	if second.RefreshToken == first.RefreshToken || second.AccessToken == first.AccessToken {
		t.Fatal("tokens did not rotate")
	}
	status, body = f.request(t, "POST", "/auth/token", "", "application/x-www-form-urlencoded", form.Encode())
	if status != 400 {
		t.Fatalf("replay %d %s", status, body)
	}
	form.Set("refresh_token", first.AccessToken)
	status, body = f.request(t, "POST", "/auth/token", "", "application/x-www-form-urlencoded", form.Encode())
	if status != 400 {
		t.Fatalf("access token accepted as refresh: %d %s", status, body)
	}
	// JSON refresh credentials work without an unexpired access token.
	status, body = f.request(t, "POST", "/auth/refresh", "", "application/json", `{"refresh_token":"`+second.RefreshToken+`"}`)
	if status != 200 {
		t.Fatalf("JSON refresh %d %s", status, body)
	}
}
func TestRefreshHTTPRejectsExpiredAndUnverifiedCredentials(t *testing.T) {
	f := newAPIFixture(t)
	ctx := context.Background()
	if err := f.db.CreateAccountToken(ctx, f.ownerID, hashToken("expired"), "refresh", time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	status, body := f.request(t, "POST", "/auth/token", "", "application/x-www-form-urlencoded", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"expired"}}.Encode())
	if status != 400 {
		t.Fatalf("expired %d %s", status, body)
	}
	unverifiedID, err := f.db.CreateUser(ctx, "unverified@example.test", "Unverified", "hash")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.CreateAccountToken(ctx, unverifiedID, hashToken("unverified"), "refresh", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	status, body = f.request(t, "POST", "/auth/token", "", "application/x-www-form-urlencoded", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"unverified"}}.Encode())
	if status != 403 {
		t.Fatalf("unverified %d %s", status, body)
	}
	// Token storage contains the digest, never the reusable bearer credential.
	handler := AuthHandler{DB: f.db}
	request := httptest.NewRequest("POST", "/", bytes.NewReader(nil))
	token, err := handler.createRefreshToken(request, f.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ConsumeAccountToken(ctx, token, "refresh"); err == nil {
		t.Fatal("plaintext refresh token was stored")
	}
}
