package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/shorebird-server/internal/models"
)

func TestHTTPRejectsDotHeavyBearerAndPreservesAuthFlows(t *testing.T) {
	f := newAPIFixture(t)
	malformed := strings.Repeat(".", 64*1024)
	for _, prefix := range []string{"", "sb_api_"} {
		for _, endpoint := range []struct{ method, path string }{
			{http.MethodGet, "/api/v1/users/me"},
			{http.MethodPost, "/auth/refresh"},
		} {
			status, body := f.request(t, endpoint.method, endpoint.path, prefix+malformed, "", "")
			if status != http.StatusUnauthorized {
				t.Fatalf("%s %s malformed bearer: status %d, want 401: %s", endpoint.method, endpoint.path, status, body)
			}
		}
	}
	status, body := f.request(t, http.MethodPost, "/auth/refresh", strings.Repeat(". ", 32*1024), "", "")
	if status != http.StatusUnauthorized {
		t.Fatalf("whitespace-heavy legacy refresh bearer: status %d, want 401: %s", status, body)
	}
	for _, prefix := range []string{"", "sb_api_"} {
		status, body := f.request(t, http.MethodGet, "/api/v1/users/me", prefix+f.owner, "", "")
		if status != http.StatusOK {
			t.Fatalf("valid bearer with prefix %q: status %d: %s", prefix, status, body)
		}
		status, body = f.request(t, http.MethodPost, "/auth/refresh", prefix+f.owner, "", "")
		if status != http.StatusOK {
			t.Fatalf("legacy refresh with prefix %q: status %d: %s", prefix, status, body)
		}
		var refreshed models.AuthTokenResponse
		if err := json.Unmarshal(body, &refreshed); err != nil {
			t.Fatal(err)
		}
		if claims, err := f.auth.ValidateToken(refreshed.Token); err != nil || claims.UserID != f.ownerID {
			t.Fatalf("invalid refreshed access token: %v", err)
		}
		if !strings.HasPrefix(refreshed.RefreshToken, "sb_rt_") {
			t.Fatal("legacy refresh did not return an opaque refresh credential")
		}
		status, body = f.request(t, http.MethodPost, "/auth/refresh", "", "application/json", `{"refresh_token":"`+refreshed.RefreshToken+`"}`)
		if status != http.StatusOK {
			t.Fatalf("opaque JSON refresh: status %d: %s", status, body)
		}
	}
}
