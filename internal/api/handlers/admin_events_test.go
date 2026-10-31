package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/shorebird-server/internal/models"
)

func TestAdminPatchEventsHTTPReturnsScopedRuntimeEvents(t *testing.T) {
	f := newAPIFixture(t)
	path := "/api/v1/admin/apps/" + f.app.ID.String() + "/events"
	foreignOrgID, err := f.db.CreateOrganization(t.Context(), "foreign", "team")
	if err != nil {
		t.Fatal(err)
	}
	foreignApp, err := f.db.CreateApp(t.Context(), foreignOrgID, "Foreign app")
	if err != nil {
		t.Fatal(err)
	}
	outsider, err := f.db.GetUserByEmail(t.Context(), "outsider@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.AddUserToOrganization(t.Context(), outsider.ID, foreignOrgID, "admin"); err != nil {
		t.Fatal(err)
	}
	if err := f.db.InsertPatchEvent(t.Context(), foreignApp.ID, "foreign-client", "aarch64", "ios", "other", "__patch_install__", 99, 1234, nil); err != nil {
		t.Fatal(err)
	}
	// This admin route retains its server-admin policy, including for an app's
	// own organization admin. Other tenants must not acquire access to events.
	for _, tc := range []struct {
		token string
		want  int
	}{{"", http.StatusUnauthorized}, {f.owner, http.StatusForbidden}, {f.reader, http.StatusForbidden}, {f.outsider, http.StatusForbidden}} {
		status, body := f.request(t, http.MethodGet, path, tc.token, "", "")
		if status != tc.want {
			t.Fatalf("event permission: status %d, want %d: %s", status, tc.want, body)
		}
	}
	if err := f.db.SetUserAdmin(t.Context(), f.ownerID, true); err != nil {
		t.Fatal(err)
	}
	for _, eventType := range []string{"__patch_download__", "__patch_install__", "__patch_install_failure__"} {
		wire := fmt.Sprintf(`{"event":{"app_id":%q,"arch":"aarch64","client_id":"runtime-client","type":%q,"patch_number":1,"platform":"ios","release_version":"1.0.0+1","timestamp":1234,"message":null}}`, f.app.ID.String(), eventType)
		status, body := f.request(t, http.MethodPost, "/api/v1/patches/events", "", "application/json", wire)
		if status != http.StatusNoContent {
			t.Fatalf("record runtime event: %d %s", status, body)
		}
	}
	list := func(query string) models.PatchEventListResponse {
		t.Helper()
		status, body := f.request(t, http.MethodGet, path+query, f.owner, "", "")
		if status != http.StatusOK {
			t.Fatalf("list events: %d %s", status, body)
		}
		var response models.PatchEventListResponse
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatal(err)
		}
		return response
	}
	all := list("")
	if len(all.Events) != 3 || all.NextBeforeID != nil {
		t.Fatalf("event list = %+v", all)
	}
	for i, event := range all.Events {
		if event.AppID != f.app.ID.String() || event.ClientID != "runtime-client" || event.PatchNumber != 1 || event.CreatedAt.IsZero() || event.Message != nil || event.Timestamp != 1234 {
			t.Fatalf("incorrect or cross-app event: %+v", event)
		}
		if i > 0 && event.ID >= all.Events[i-1].ID {
			t.Fatal("events are not newest first")
		}
	}
	if all.Events[0].Type != "__patch_install_failure__" || all.Events[2].Type != "__patch_download__" {
		t.Fatalf("runtime event identifiers changed: %+v", all.Events)
	}
	page := list("?limit=2")
	if len(page.Events) != 2 || page.NextBeforeID == nil || *page.NextBeforeID != page.Events[1].ID {
		t.Fatalf("first page = %+v", page)
	}
	next := list(fmt.Sprintf("?limit=2&before_id=%d", *page.NextBeforeID))
	if len(next.Events) != 1 || next.NextBeforeID != nil || next.Events[0].ID != all.Events[2].ID {
		t.Fatalf("next page = %+v", next)
	}
	empty := list(fmt.Sprintf("?before_id=%d", all.Events[2].ID))
	if empty.Events == nil || len(empty.Events) != 0 || empty.NextBeforeID != nil {
		t.Fatalf("empty page = %+v", empty)
	}
	for _, query := range []string{"?limit=0", "?limit=-1", "?limit=501", "?limit=bad", "?before_id=0", "?before_id=-1", "?before_id=bad", "?before_id=9223372036854775808"} {
		status, body := f.request(t, http.MethodGet, path+query, f.owner, "", "")
		if status != http.StatusBadRequest {
			t.Fatalf("invalid cursor/limit %s: %d %s", query, status, body)
		}
	}
	for _, tc := range []struct {
		appID string
		want  int
	}{{"bad-uuid", http.StatusBadRequest}, {uuid.NewString(), http.StatusNotFound}} {
		status, body := f.request(t, http.MethodGet, "/api/v1/admin/apps/"+tc.appID+"/events", f.owner, "", "")
		if status != tc.want {
			t.Fatalf("app validation: %d, want %d: %s", status, tc.want, body)
		}
	}
	for i := 0; i < 101; i++ {
		if err := f.db.InsertPatchEvent(t.Context(), f.app.ID, "pagination-client", "aarch64", "ios", "1.0.0+1", "__patch_install__", 1, 1234, nil); err != nil {
			t.Fatal(err)
		}
	}
	defaultPage := list("")
	if len(defaultPage.Events) != 100 || defaultPage.NextBeforeID == nil {
		t.Fatalf("default event page is not bounded to 100: %d events", len(defaultPage.Events))
	}
	maximumPage := list("?limit=500")
	if len(maximumPage.Events) != 104 || maximumPage.NextBeforeID != nil {
		t.Fatalf("maximum event page: %+v", maximumPage)
	}
}
