package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/shorebird-server/internal/auth"
	"github.com/shorebird-server/internal/db"
	"github.com/shorebird-server/internal/models"
)

func TestPatchEventMetadataRetriesAndRestartHTTP(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			f, otherApp, reopen := newEventMetadataFixture(t, backend)
			eventID := uuid.NewString()
			// This envelope and optional-field order match the native serde wire format.
			wire := fmt.Sprintf(`{"event":{"app_id":%q,"arch":"aarch64","client_id":"runtime-client","type":"__patch_update_failure__","patch_number":1,"platform":"ios","release_version":"1.0.0+1","timestamp":1234,"message":"original failure","failure_category":"network","event_id":%q}}`, f.app.ID.String(), eventID)
			post := func(body string) {
				t.Helper()
				status, data := f.request(t, http.MethodPost, "/api/v1/patches/events", "", "application/json", body)
				if status != http.StatusNoContent {
					t.Fatalf("event ingestion: %d %s", status, data)
				}
			}
			postEventsConcurrently(t, f.server, wire, 16)
			// A conflicting retry also succeeds, but the first event is immutable.
			post(strings.ReplaceAll(strings.ReplaceAll(wire, "original failure", "conflicting failure"), `"network"`, `"server"`))
			post(strings.Replace(wire, eventID, strings.ToUpper(eventID), 1))
			list := func(appID string) []models.PatchEventRecord {
				t.Helper()
				status, data := f.request(t, http.MethodGet, "/api/v1/admin/apps/"+appID+"/events", f.owner, "", "")
				if status != http.StatusOK {
					t.Fatalf("event history: %d %s", status, data)
				}
				var response models.PatchEventListResponse
				if err := json.Unmarshal(data, &response); err != nil {
					t.Fatal(err)
				}
				return response.Events
			}
			initial := list(f.app.ID.String())
			if len(initial) != 1 || initial[0].EventID == nil || *initial[0].EventID != eventID || initial[0].FailureCategory == nil || *initial[0].FailureCategory != "network" || initial[0].Message == nil || *initial[0].Message != "original failure" {
				t.Fatalf("retry deduplication or first-write-wins failed: %+v", initial)
			}
			originalRowID := initial[0].ID
			post(strings.Replace(wire, f.app.ID.String(), otherApp.String(), 1))
			post(strings.Replace(wire, "runtime-client", "another-client", 1))
			if rows := list(otherApp.String()); len(rows) != 1 || rows[0].AppID != otherApp.String() {
				t.Fatalf("event UUID collided across apps: %+v", rows)
			}
			legacy := strings.Replace(wire, `,"event_id":"`+eventID+`"`, "", 1)
			postEventsConcurrently(t, f.server, legacy, 8)
			post(strings.Replace(wire, `"event_id":"`+eventID+`"`, `"event_id":null`, 1))
			if rows := list(f.app.ID.String()); len(rows) != 11 {
				t.Fatalf("legacy events were lost: got %d, want 11", len(rows))
			}
			reopen()
			post(wire)
			rows := list(f.app.ID.String())
			if len(rows) != 11 {
				t.Fatalf("retry after restart duplicated an event: got %d rows", len(rows))
			}
			var identified, legacyCount int
			for _, event := range rows {
				if event.EventID == nil {
					legacyCount++
				} else {
					identified++
					if event.ClientID == "runtime-client" && (event.ID != originalRowID || event.Message == nil || *event.Message != "original failure") {
						t.Fatalf("original event changed across restart: %+v", event)
					}
				}
				if event.FailureCategory == nil || *event.FailureCategory != "network" {
					t.Fatalf("failure category lost across restart: %+v", event)
				}
			}
			if identified != 2 || legacyCount != 9 {
				t.Fatalf("identified = %d, legacy = %d", identified, legacyCount)
			}
		})
	}
}

func postEventsConcurrently(t *testing.T, server *httptest.Server, wire string, count int) {
	t.Helper()
	start := make(chan struct{})
	errors := make(chan error, count)
	var workers sync.WaitGroup
	for i := 0; i < count; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			response, err := server.Client().Post(server.URL+"/api/v1/patches/events", "application/json", strings.NewReader(wire))
			if err == nil {
				_, err = io.Copy(io.Discard, response.Body)
				response.Body.Close()
				if response.StatusCode != http.StatusNoContent {
					err = fmt.Errorf("concurrent event status = %d", response.StatusCode)
				}
			}
			errors <- err
		}()
	}
	close(start)
	workers.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func newEventMetadataFixture(t *testing.T, backend string) (*apiFixture, uuid.UUID, func()) {
	t.Helper()
	dsn := t.TempDir() + "/server.db"
	if backend == "postgres" {
		dsn = os.Getenv("SHOREBIRD_TEST_POSTGRES_DSN")
		if dsn == "" {
			t.Skip("set SHOREBIRD_TEST_POSTGRES_DSN to an isolated migrated PostgreSQL database")
		}
	}
	open := func() db.Store {
		t.Helper()
		store, err := db.NewStore(t.Context(), backend, dsn)
		if err != nil {
			t.Fatal(err)
		}
		return store
	}
	f := &apiFixture{db: open(), auth: auth.NewService("metadata-test-secret", time.Hour)}
	var apps []uuid.UUID
	var orgs []int
	t.Cleanup(func() {
		if f.server != nil {
			f.server.Close()
		}
		f.db.Close()
		if backend == "postgres" {
			connection, err := pgx.Connect(context.Background(), dsn)
			if err != nil {
				t.Error(err)
				return
			}
			defer connection.Close(context.Background())
			for _, id := range apps {
				_, _ = connection.Exec(context.Background(), "DELETE FROM patch_events WHERE app_id = $1", id)
			}
			for _, id := range orgs {
				_, _ = connection.Exec(context.Background(), "DELETE FROM organizations WHERE id = $1", id)
			}
			_, _ = connection.Exec(context.Background(), "DELETE FROM users WHERE id = $1", f.ownerID)
		}
	})
	for i := 0; i < 2; i++ {
		orgID, err := f.db.CreateOrganization(t.Context(), "metadata-test", "team")
		if err != nil {
			t.Fatal(err)
		}
		orgs = append(orgs, orgID)
		app, err := f.db.CreateApp(t.Context(), orgID, "metadata-test")
		if err != nil {
			t.Fatal(err)
		}
		apps = append(apps, app.ID)
		if i == 0 {
			f.app = app
		}
	}
	email := uuid.NewString() + "@example.test"
	var err error
	f.ownerID, err = f.db.CreateUser(t.Context(), email, "metadata-test", "unused")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.MarkUserEmailVerified(t.Context(), f.ownerID); err != nil {
		t.Fatal(err)
	}
	if err := f.db.SetUserAdmin(t.Context(), f.ownerID, true); err != nil {
		t.Fatal(err)
	}
	f.owner, err = f.auth.GenerateToken(f.ownerID, email)
	if err != nil {
		t.Fatal(err)
	}
	f.server = httptest.NewServer(NewRouter(f.auth, f.db, nil, nil, "", PatchDeliveryConfig{}))
	reopen := func() {
		t.Helper()
		f.server.Close()
		f.db.Close()
		f.db = open()
		f.server = httptest.NewServer(NewRouter(f.auth, f.db, nil, nil, "", PatchDeliveryConfig{}))
	}
	return f, apps[1], reopen
}

func TestPatchEventMetadataValidationHTTP(t *testing.T) {
	f := newAPIFixture(t)
	base := map[string]interface{}{
		"app_id": f.app.ID.String(), "arch": "aarch64", "client_id": "runtime-client",
		"type": "__patch_update_failure__", "patch_number": 1, "platform": "ios",
		"release_version": "1.0.0+1", "timestamp": 1234, "message": nil,
		"failure_category": "network", "event_id": uuid.NewString(),
	}
	encode := func(fields map[string]interface{}) string {
		t.Helper()
		data, err := json.Marshal(map[string]interface{}{"event": fields})
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	for _, tc := range []struct {
		field string
		value interface{}
	}{
		{"event_id", ""}, {"event_id", "not-a-uuid"}, {"event_id", uuid.Nil.String()}, {"event_id", 1},
		{"failure_category", ""}, {"failure_category", strings.Repeat("a", 129)}, {"failure_category", "network\ntrace"}, {"failure_category", "network error"},
		{"client_id", ""}, {"client_id", strings.Repeat("a", 257)}, {"arch", strings.Repeat("a", 65)}, {"platform", strings.Repeat("a", 65)},
		{"release_version", strings.Repeat("a", 1025)}, {"message", strings.Repeat("a", 32*1024+1)},
		{"patch_number", -1}, {"patch_number", int64(2147483648)}, {"timestamp", -1},
	} {
		fields := make(map[string]interface{}, len(base))
		for key, value := range base {
			fields[key] = value
		}
		fields[tc.field] = tc.value
		status, body := f.request(t, http.MethodPost, "/api/v1/patches/events", "", "application/json", encode(fields))
		if status != http.StatusBadRequest {
			t.Fatalf("invalid %s: status %d, body %s", tc.field, status, body)
		}
	}
	for _, category := range []string{"network", "server", "out_of_space", "permission_denied", "filesystem", "corrupt_patch", "invalid_signature", "unknown", "future.category-v2", strings.Repeat("a", 128)} {
		base["failure_category"] = category
		base["event_id"] = uuid.NewString()
		status, body := f.request(t, http.MethodPost, "/api/v1/patches/events", "", "application/json", encode(base))
		if status != http.StatusNoContent {
			t.Fatalf("category %q rejected: %d %s", category, status, body)
		}
	}
	base["client_id"] = strings.Repeat("a", 256)
	base["arch"] = strings.Repeat("a", 64)
	base["platform"] = strings.Repeat("a", 64)
	base["release_version"] = strings.Repeat("a", 1024)
	base["message"] = strings.Repeat("a", 32*1024)
	base["event_id"] = "018f6b0e-3c87-7cc2-8c32-8392f0123456" // Allow future UUID versions.
	valid := encode(base)
	status, body := f.request(t, http.MethodPost, "/api/v1/patches/events", "", "application/json", valid)
	if status != http.StatusNoContent {
		t.Fatalf("valid boundary values rejected: %d %s", status, body)
	}
	for _, wire := range []string{valid + "{}", valid + " malformed"} {
		status, body = f.request(t, http.MethodPost, "/api/v1/patches/events", "", "application/json", wire)
		if status != http.StatusBadRequest {
			t.Fatalf("trailing JSON accepted: %d %s", status, body)
		}
	}
	status, body = f.request(t, http.MethodPost, "/api/v1/patches/events", "", "application/json", valid+strings.Repeat(" ", maxPatchEventRequestBytes-len(valid)))
	if status != http.StatusNoContent {
		t.Fatalf("body at size limit rejected: %d %s", status, body)
	}
	for _, wire := range []string{valid + strings.Repeat(" ", maxPatchEventRequestBytes), `{"event":{"message":"` + strings.Repeat("a", maxPatchEventRequestBytes) + `"}}`} {
		status, body = f.request(t, http.MethodPost, "/api/v1/patches/events", "", "application/json", wire)
		if status != http.StatusRequestEntityTooLarge {
			t.Fatalf("oversized event body: %d %s", status, body)
		}
	}
}
