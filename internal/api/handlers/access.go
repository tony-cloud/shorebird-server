package handlers

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/shorebird-server/internal/api/middleware"
	"github.com/shorebird-server/internal/db"
)

func requireAppAccess(w http.ResponseWriter, r *http.Request, store db.Store, appID uuid.UUID, manage bool) (*db.AppRow, bool) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		respondError(w, http.StatusUnauthorized, "Unauthorized", nil)
		return nil, false
	}
	app, err := store.GetAppByID(r.Context(), appID)
	if err != nil {
		respondError(w, http.StatusNotFound, "App not found", nil)
		return nil, false
	}
	if canAccessOrganization(r, store, claims.UserID, app.OrganizationID, manage) {
		return app, true
	}
	if manage {
		respondError(w, http.StatusForbidden, "Organization admin access required", nil)
	} else {
		respondError(w, http.StatusForbidden, "Organization access required", nil)
	}
	return nil, false
}

func canAccessOrganization(r *http.Request, store db.Store, userID, orgID int, manage bool) bool {
	user, _ := store.GetUserByID(r.Context(), userID)
	if user != nil && user.IsAdmin {
		return true
	}
	role, err := store.GetOrganizationRole(r.Context(), userID, orgID)
	if err != nil {
		return false
	}
	if manage {
		return role == "admin"
	}
	return role != ""
}
