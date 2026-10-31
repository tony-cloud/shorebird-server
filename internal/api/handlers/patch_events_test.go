package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/shorebird-server/internal/auth"
	"github.com/shorebird-server/internal/db"
	"github.com/shorebird-server/internal/models"
)

func TestPatchEventsAcceptsRuntimeWireFormatAndLegacyAliasesHTTP(t *testing.T) {
	f := newAPIFixture(t)
	database, err := sql.Open("sqlite", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	for i, tc := range []struct {
		name, wireType, storedType, messageJSON, message, extra string
	}{
		{"boot success", "__patch_install__", "__patch_install__", "null", "", ""},
		{"boot failure", "__patch_install_failure__", "__patch_install_failure__", `"engine_report: patch 1 failed to launch"`, "engine_report: patch 1 failed to launch", ""},
		{"download", "__patch_download__", "__patch_download__", "null", "", ""},
		{"update failure", "__patch_update_failure__", "__patch_update_failure__", `"download failed"`, "download failed", `,"failure_category":"network","event_id":"11111111-2222-4333-8444-555555555555"`},
		{"legacy boot success", "PatchInstallSuccess", "__patch_install__", "null", "", ""},
		{"legacy boot failure", "PatchInstallFailure", "__patch_install_failure__", `"legacy failure"`, "legacy failure", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientID := fmt.Sprintf("event-client-%d", i)
			// Field order and envelope match CreatePatchEventRequest's serde
			// serialization fixture in updater/library/src/network.rs.
			wire := fmt.Sprintf(`{"event":{"app_id":%q,"arch":"aarch64","client_id":%q,"type":%q,"patch_number":1,"platform":"ios","release_version":"1.0.0+1","timestamp":1234,"message":%s%s}}`, f.app.ID.String(), clientID, tc.wireType, tc.messageJSON, tc.extra)
			status, body := f.request(t, http.MethodPost, "/api/v1/patches/events", "", "application/json", wire)
			if status != http.StatusNoContent || len(body) != 0 {
				t.Fatalf("runtime event: status %d, body %s", status, body)
			}
			var appID, arch, platform, releaseVersion, eventType string
			var patchNumber int
			var timestamp int64
			var message sql.NullString
			err := database.QueryRow(`SELECT app_id, arch, platform, release_version, event_type, patch_number, timestamp, message FROM patch_events WHERE client_id = ?`, clientID).Scan(&appID, &arch, &platform, &releaseVersion, &eventType, &patchNumber, &timestamp, &message)
			if err != nil {
				t.Fatal(err)
			}
			if appID != f.app.ID.String() || arch != "aarch64" || platform != "ios" || releaseVersion != "1.0.0+1" || eventType != tc.storedType || patchNumber != 1 || timestamp != 1234 || message.Valid != (tc.messageJSON != "null") || message.String != tc.message {
				t.Fatalf("incorrect persisted event: %s %s %s %s %s %d %d %+v", appID, arch, platform, releaseVersion, eventType, patchNumber, timestamp, message)
			}
		})
	}
}

func TestPatchEventsPostgresRuntimeMessageHTTP(t *testing.T) {
	dsn := os.Getenv("SHOREBIRD_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set SHOREBIRD_TEST_POSTGRES_DSN to an isolated migrated PostgreSQL database")
	}
	store, err := db.NewPostgresStore(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	connection, err := pgx.Connect(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connection.Close(context.Background()) })
	orgID, err := store.CreateOrganization(t.Context(), "Event test", "team")
	if err != nil {
		t.Fatal(err)
	}
	app, err := store.CreateApp(t.Context(), orgID, "Event test")
	if err != nil {
		t.Fatal(err)
	}
	appID := app.ID
	userID, err := store.CreateUser(t.Context(), uuid.NewString()+"@example.test", "Event admin", "unused")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkUserEmailVerified(t.Context(), userID); err != nil {
		t.Fatal(err)
	}
	if err := store.SetUserAdmin(t.Context(), userID, true); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = connection.Exec(context.Background(), "DELETE FROM users WHERE id = $1", userID)
		_, _ = connection.Exec(context.Background(), "DELETE FROM organizations WHERE id = $1", orgID)
	})
	t.Cleanup(func() {
		_, _ = connection.Exec(context.Background(), "DELETE FROM patch_events WHERE app_id = $1", appID)
	})
	service := auth.NewService("event-test-secret", time.Hour)
	token, err := service.GenerateToken(userID, "event-admin@example.test")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(NewRouter(service, store, nil, nil, "", PatchDeliveryConfig{}))
	t.Cleanup(server.Close)
	f := &apiFixture{server: server}
	for _, eventType := range []string{"__patch_install__", "__patch_install_failure__", "__patch_download__", "__patch_update_failure__"} {
		message := `engine_report: patch 1 failed to launch ("diagnostic")`
		messageJSON := []byte("null")
		hasMessage := strings.Contains(eventType, "failure")
		if hasMessage {
			messageJSON, err = json.Marshal(message)
			if err != nil {
				t.Fatal(err)
			}
		}
		wire := fmt.Sprintf(`{"event":{"app_id":%q,"arch":"aarch64","client_id":"pg-event-client","type":%q,"patch_number":1,"platform":"ios","release_version":"1.0.0+1","timestamp":1234,"message":%s}}`, appID.String(), eventType, messageJSON)
		status, body := f.request(t, http.MethodPost, "/api/v1/patches/events", "", "application/json", wire)
		if status != http.StatusNoContent {
			t.Fatalf("PostgreSQL runtime event %s: status %d, body %s", eventType, status, body)
		}
		var storedMessage sql.NullString
		if err := connection.QueryRow(t.Context(), "SELECT message::text FROM patch_events WHERE app_id = $1 AND event_type = $2", appID, eventType).Scan(&storedMessage); err != nil {
			t.Fatal(err)
		}
		if storedMessage.Valid != hasMessage {
			t.Fatalf("PostgreSQL message nullability = %v, want %v", storedMessage.Valid, hasMessage)
		}
		if hasMessage {
			var decoded string
			if err := json.Unmarshal([]byte(storedMessage.String), &decoded); err != nil || decoded != message {
				t.Fatalf("PostgreSQL message = %q, decode error = %v", storedMessage.String, err)
			}
		}
	}
	path := "/api/v1/admin/apps/" + appID.String() + "/events?limit=2"
	var previousID int64
	for page := 0; page < 2; page++ {
		status, body := f.request(t, http.MethodGet, path, token, "", "")
		if status != http.StatusOK {
			t.Fatalf("PostgreSQL event list: %d %s", status, body)
		}
		var response models.PatchEventListResponse
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatal(err)
		}
		if len(response.Events) != 2 || (response.NextBeforeID != nil) != (page == 0) {
			t.Fatalf("PostgreSQL event page = %+v", response)
		}
		for _, event := range response.Events {
			if event.AppID != appID.String() || event.CreatedAt.IsZero() || (previousID != 0 && event.ID >= previousID) {
				t.Fatalf("incorrect PostgreSQL event: %+v", event)
			}
			if strings.Contains(event.Type, "failure") {
				if event.Message == nil || *event.Message != `engine_report: patch 1 failed to launch ("diagnostic")` {
					t.Fatalf("message was not decoded from JSONB: %+v", event)
				}
			} else if event.Message != nil {
				t.Fatalf("null message changed: %+v", event)
			}
			previousID = event.ID
		}
		if response.NextBeforeID != nil {
			path += fmt.Sprintf("&before_id=%d", *response.NextBeforeID)
		}
	}
}

func TestPatchEventsRejectsInvalidWireInputHTTP(t *testing.T) {
	f := newAPIFixture(t)
	valid := fmt.Sprintf(`{"event":{"app_id":%q,"arch":"aarch64","client_id":"event-client","type":"__patch_install__","patch_number":1,"platform":"ios","release_version":"1.0.0+1","timestamp":1234,"message":null}}`, f.app.ID.String())
	for _, wire := range []string{
		strings.Replace(valid, "__patch_install__", "__bogus__", 1),
		strings.Replace(valid, "__patch_install__", "", 1),
		strings.Replace(valid, f.app.ID.String(), "not-an-app-uuid", 1),
		strings.Replace(valid, `"type":"__patch_install__"`, `"type":1`, 1),
		`{"event":null}`,
		`{`,
	} {
		status, body := f.request(t, http.MethodPost, "/api/v1/patches/events", "", "application/json", wire)
		if status != http.StatusBadRequest {
			t.Fatalf("invalid event accepted: status %d, body %s", status, body)
		}
	}
	events, err := f.db.ListPatchEventActivity(t.Context(), f.app.ID, 0, 0)
	if err != nil || len(events) != 0 {
		t.Fatalf("invalid events reached storage: %+v, %v", events, err)
	}
}
