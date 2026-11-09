package handlers

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shorebird-server/internal/updater"
)

type updateTestSource struct{}

func (updateTestSource) Latest(context.Context, string) (*updater.Release, error) { return nil, nil }
func (updateTestSource) Download(context.Context, *updater.Release, io.Writer) error {
	return nil
}

type updateTestInstaller struct {
	mu        sync.Mutex
	previous  string
	rollbacks int
}

func (i *updateTestInstaller) Install(context.Context, updater.Source, *updater.Release) error {
	return nil
}
func (i *updateTestInstaller) RollbackInfo() (string, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.previous, i.previous != ""
}
func (i *updateTestInstaller) ManualRollback() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.rollbacks++
	i.previous = ""
	return nil
}

type updateFixture struct {
	*apiFixture
	server    *httptest.Server
	installer *updateTestInstaller
	audit     string
}

func newUpdateFixture(t *testing.T, active bool) *updateFixture {
	t.Helper()
	f := newAPIFixture(t)
	if err := f.db.SetUserAdmin(t.Context(), f.ownerID, true); err != nil {
		t.Fatal(err)
	}
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	trust, err := updater.NewTrust(base64.StdEncoding.EncodeToString(public), false)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	installer := &updateTestInstaller{previous: "v1.0.0"}
	platform := updater.Platform{GOOS: "linux", GOARCH: "amd64"}
	var service *updater.Service
	if active {
		service, err = updater.New(updater.Options{ConfigPath: filepath.Join(dir, "server-update.json"), Version: "v1.1.0", Source: updateTestSource{},
			Installer: installer, Restart: func() {}, TempDir: dir, Trust: trust, Platform: platform})
		if err != nil {
			t.Fatal(err)
		}
	} else {
		service = updater.NewInactive(updater.Plan{Mode: updater.ModeManagedExternally, ManagedBy: "docker", Reason: "immutable_image"}, "v1.1.0", platform)
	}
	t.Cleanup(service.Close)
	auditPath := filepath.Join(dir, "audit.jsonl")
	router := NewRouterWithOptions(f.auth, f.db, f.objects, nil, "", PatchDeliveryConfig{}, RouterOptions{
		ServerUpdate: &ServerUpdateHandler{DB: f.db, Service: service, Auditor: updater.NewFileAuditor(auditPath)},
	})
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	f.server = server
	return &updateFixture{apiFixture: f, server: server, installer: installer, audit: auditPath}
}

func decodeCode(t *testing.T, body []byte) string {
	t.Helper()
	var payload struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(body, &payload)
	return payload.Code
}

func TestServerUpdateRequiresGlobalAdmin(t *testing.T) {
	f := newUpdateFixture(t, true)
	if err := f.db.SetUserAdmin(t.Context(), f.ownerID, false); err != nil {
		t.Fatal(err)
	}
	// The owner is an organization admin, which grants nothing here.
	for _, route := range []struct{ method, path, contentType, body string }{
		{http.MethodGet, "/api/v1/admin/server/update", "", ""},
		{http.MethodPut, "/api/v1/admin/server/update", "application/json", `{"auto_update":true,"check_interval_seconds":3600}`},
		{http.MethodPost, "/api/v1/admin/server/update/check", "", ""},
		{http.MethodPost, "/api/v1/admin/server/update/install", "application/json", `{"version":"v1.2.0"}`},
		{http.MethodPost, "/api/v1/admin/server/update/upload", "application/zip", "PK"},
		{http.MethodPost, "/api/v1/admin/server/update/rollback", "application/json", `{"current_password":"test-password","current_version":"v1.1.0","rollback_version":"v1.0.0"}`},
		{http.MethodGet, "/api/v1/admin/server/update/audit", "", ""},
	} {
		if status, body := f.request(t, route.method, route.path, "", route.contentType, route.body); status != http.StatusUnauthorized {
			t.Errorf("%s %s anonymous: %d %s", route.method, route.path, status, body)
		}
		for _, token := range []string{f.owner, f.reader, f.outsider} {
			if status, body := f.request(t, route.method, route.path, token, route.contentType, route.body); status != http.StatusForbidden || decodeCode(t, body) != "admin_required" {
				t.Errorf("%s %s non-admin: %d %s", route.method, route.path, status, body)
			}
		}
	}
	if f.installer.rollbacks != 0 {
		t.Fatal("a non-admin rolled the server back")
	}
}

func TestServerUpdateSettingsAndStatus(t *testing.T) {
	f := newUpdateFixture(t, true)
	status, body := f.request(t, http.MethodGet, "/api/v1/admin/server/update", f.owner, "", "")
	if status != http.StatusOK {
		t.Fatalf("%d %s", status, body)
	}
	var st updater.Status
	_ = json.Unmarshal(body, &st)
	if st.Mode != "active" || st.CurrentVersion != "v1.1.0" || st.Channel != "stable" || st.CheckIntervalSeconds != 86400 || st.RollbackVersion != "v1.0.0" {
		t.Fatalf("status %+v", st)
	}
	status, body = f.request(t, http.MethodPut, "/api/v1/admin/server/update", f.owner, "application/json", `{"auto_update":true,"check_interval_seconds":3600,"channel":"dev","use_mirror":true}`)
	if status != http.StatusOK {
		t.Fatalf("%d %s", status, body)
	}
	_ = json.Unmarshal(body, &st)
	if !st.AutoUpdate || st.Channel != "dev" || !st.UseMirror || st.CheckIntervalSeconds != 3600 {
		t.Fatalf("settings %+v", st)
	}
	for body, want := range map[string]string{
		`{"auto_update":true}`:                                                "invalid_config",
		`{"auto_update":true,"check_interval_seconds":10}`:                    "invalid_interval",
		`{"auto_update":true,"check_interval_seconds":3600,"channel":"beta"}`: "invalid_channel",
		`{"auto_update":true,"check_interval_seconds":3600,"repository":"x"}`: "invalid_config",
	} {
		if status, resp := f.request(t, http.MethodPut, "/api/v1/admin/server/update", f.owner, "application/json", body); status != http.StatusBadRequest || decodeCode(t, resp) != want {
			t.Errorf("%s: %d %s", body, status, resp)
		}
	}
	if status, body := f.request(t, http.MethodPost, "/api/v1/admin/server/update/install", f.owner, "application/json", `{"version":"v1.2.0"}`); status != http.StatusConflict || decodeCode(t, body) != "check_required" {
		t.Fatalf("install without check: %d %s", status, body)
	}
	if status, body := f.request(t, http.MethodPost, "/api/v1/admin/server/update/upload", f.owner, "text/plain", "x"); status != http.StatusUnsupportedMediaType {
		t.Fatalf("upload content type: %d %s", status, body)
	}
	if status, body := f.request(t, http.MethodPost, "/api/v1/admin/server/update/upload", f.owner, "application/zip", "not a zip"); status != http.StatusUnprocessableEntity || decodeCode(t, body) != "invalid_zip" {
		t.Fatalf("invalid zip: %d %s", status, body)
	}
}

func TestServerUpdateManagedExternally(t *testing.T) {
	f := newUpdateFixture(t, false)
	status, body := f.request(t, http.MethodGet, "/api/v1/admin/server/update", f.owner, "", "")
	var st updater.Status
	_ = json.Unmarshal(body, &st)
	if status != http.StatusOK || st.Mode != "managed_externally" || st.ManagedBy != "docker" {
		t.Fatalf("%d %s", status, body)
	}
	for _, route := range []struct{ method, path, contentType, body string }{
		{http.MethodPut, "/api/v1/admin/server/update", "application/json", `{"auto_update":true,"check_interval_seconds":3600}`},
		{http.MethodPost, "/api/v1/admin/server/update/check", "", ""},
		{http.MethodPost, "/api/v1/admin/server/update/upload", "application/zip", "PK"},
		{http.MethodPost, "/api/v1/admin/server/update/rollback", "application/json", `{"current_password":"test-password","current_version":"v1.1.0","rollback_version":"v1.0.0"}`},
	} {
		if status, body := f.request(t, route.method, route.path, f.owner, route.contentType, route.body); status != http.StatusConflict || decodeCode(t, body) != "managed_externally" {
			t.Errorf("%s %s: %d %s", route.method, route.path, status, body)
		}
	}
}

func TestServerRollbackReauthentication(t *testing.T) {
	f := newUpdateFixture(t, true)
	path := "/api/v1/admin/server/update/rollback"
	body := func(password, current, previous string) string {
		data, _ := json.Marshal(map[string]string{"current_password": password, "current_version": current, "rollback_version": previous})
		return string(data)
	}
	// Version conflicts are refused before a password attempt is spent.
	if status, resp := f.request(t, http.MethodPost, path, f.owner, "application/json", body("wrong", "v1.1.0", "v0.9.0")); status != http.StatusConflict || decodeCode(t, resp) != "rollback_conflict" {
		t.Fatalf("conflict: %d %s", status, resp)
	}
	if status, resp := f.request(t, http.MethodPost, path, f.owner, "application/json", body("", "v1.1.0", "v1.0.0")); status != http.StatusForbidden || decodeCode(t, resp) != "RECENT_AUTH_REQUIRED" {
		t.Fatalf("missing password: %d %s", status, resp)
	}
	for n := 0; n < 5; n++ {
		if status, resp := f.request(t, http.MethodPost, path, f.owner, "application/json", body("wrong-password-"+string(rune('a'+n)), "v1.1.0", "v1.0.0")); status != http.StatusUnauthorized || decodeCode(t, resp) != "REAUTH_FAILED" {
			t.Fatalf("wrong password %d: %d %s", n, status, resp)
		}
	}
	if status, resp := f.request(t, http.MethodPost, path, f.owner, "application/json", body("test-password", "v1.1.0", "v1.0.0")); status != http.StatusTooManyRequests {
		t.Fatalf("rate limit: %d %s", status, resp)
	}
	if f.installer.rollbacks != 0 {
		t.Fatal("rolled back without verification")
	}
	// A fresh limiter window (simulated) lets the correct password through.
	handlerReset(t)
	status, resp := f.request(t, http.MethodPost, path, f.owner, "application/json", body("test-password", "v1.1.0", "v1.0.0"))
	if status != http.StatusAccepted || f.installer.rollbacks != 1 {
		t.Fatalf("rollback: %d %s", status, resp)
	}
	var st updater.Status
	_ = json.Unmarshal(resp, &st)
	if st.LastRollback != "manual" || st.RolledBackVersion != "v1.1.0" {
		t.Fatalf("status %+v", st)
	}
	// The audit trail names the actor and outcome, never the password.
	data, err := os.ReadFile(f.audit)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "test-password") || strings.Contains(string(data), "wrong-password") || strings.Contains(string(data), f.owner) {
		t.Fatal("audit log contains a secret")
	}
	if !strings.Contains(string(data), `"result":"REAUTH_FAILED"`) || !strings.Contains(string(data), `"result":"started"`) || !strings.Contains(string(data), `"actor_email":"owner@example.test"`) {
		t.Fatalf("audit log incomplete:\n%s", data)
	}
	status, resp = f.request(t, http.MethodGet, "/api/v1/admin/server/update/audit?limit=2", f.owner, "", "")
	var audit struct {
		Events []updater.AuditEvent `json:"events"`
	}
	_ = json.Unmarshal(resp, &audit)
	if status != http.StatusOK || len(audit.Events) != 2 || audit.Events[0].Result != "started" || audit.Events[0].Auth != "password" {
		t.Fatalf("audit endpoint: %d %s", status, resp)
	}
}

// handlerReset advances the limiter clock past the failure window.
func handlerReset(t *testing.T) {
	reauthNow = func() time.Time { return time.Now().Add(reauthWindow) }
	t.Cleanup(func() { reauthNow = time.Now })
}
