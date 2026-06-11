package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/shorebird-server/internal/api/middleware"
	"github.com/shorebird-server/internal/db"
	"github.com/shorebird-server/internal/models"
)

// strPtr returns a pointer to a string.
func strPtr(s string) *string {
	return &s
}

// intPtr returns a pointer to an int.
func intPtr(i int) *int {
	return &i
}

// UserHandler handles user-related API endpoints.
type UserHandler struct {
	DB *db.DB
}

// GetCurrentUser handles GET /api/v1/users/me
func (h *UserHandler) GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		respondError(w, http.StatusUnauthorized, "Unauthorized", nil)
		return
	}

	user, err := h.DB.GetUserByID(r.Context(), claims.UserID)
	if err != nil {
		respondError(w, http.StatusNotFound, "User not found", nil)
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"id":         user.ID,
		"email":      user.Email,
		"name":       user.Name,
		"created_at": user.CreatedAt,
	})
}

// CreateUser handles POST /api/v1/users
func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		respondError(w, http.StatusUnauthorized, "Unauthorized", nil)
		return
	}

	var req models.CreateUserRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}

	// In the Shorebird protocol, user creation during login flow
	// is handled by the auth server. For API completeness, this
	// endpoint updates the user's name if they exist.
	user, err := h.DB.GetUserByEmail(r.Context(), claims.Email)
	if err != nil {
		respondError(w, http.StatusNotFound, "User not found", nil)
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"id":         user.ID,
		"email":      user.Email,
		"name":       user.Name,
		"created_at": user.CreatedAt,
	})
}

// AppHandler handles app-related API endpoints.
type AppHandler struct {
	DB *db.DB
}

// GetApps handles GET /api/v1/apps
func (h *AppHandler) GetApps(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		respondError(w, http.StatusUnauthorized, "Unauthorized", nil)
		return
	}

	apps, err := h.DB.GetAppsByUserID(r.Context(), claims.UserID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch apps", nil)
		return
	}

	var result []models.AppMetadata
	for _, a := range apps {
		result = append(result, models.AppMetadata{
			AppID:       a.ID.String(),
			DisplayName: a.DisplayName,
			CreatedAt:   a.CreatedAt,
			UpdatedAt:   a.UpdatedAt,
		})
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{"apps": result})
}

// CreateApp handles POST /api/v1/apps
func (h *AppHandler) CreateApp(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		respondError(w, http.StatusUnauthorized, "Unauthorized", nil)
		return
	}

	var req models.CreateAppRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}

	if req.OrganizationID == 0 {
		// Default to user's first organization
		orgs, err := h.DB.GetOrganizationsByUserID(r.Context(), claims.UserID)
		if err != nil || len(orgs) == 0 {
			// Create a default org
			orgID, err := h.DB.CreateOrganization(r.Context(), claims.Email+"'s Org", "team")
			if err != nil {
				respondError(w, http.StatusInternalServerError, "Failed to create organization", nil)
				return
			}
			h.DB.AddUserToOrganization(r.Context(), claims.UserID, orgID, "admin")
			req.OrganizationID = orgID
		} else {
			req.OrganizationID = orgs[0].OrgID
		}
	}

	app, err := h.DB.CreateApp(r.Context(), req.OrganizationID, req.DisplayName)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create app", strPtr(err.Error()))
		return
	}

	// Auto-create default "stable" channel
	_, err = h.DB.CreateChannel(r.Context(), app.ID, "stable")
	if err != nil {
		// Log but don't fail; channel creation is best-effort for compat
	}

	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"app_id":       app.ID.String(),
		"display_name": app.DisplayName,
		"created_at":   app.CreatedAt,
		"updated_at":   app.UpdatedAt,
	})
}

// DeleteApp handles DELETE /api/v1/apps/{appId}
func (h *AppHandler) DeleteApp(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appId")
	id, err := parseUUID(appID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid app ID", nil)
		return
	}

	if err := h.DB.DeleteApp(r.Context(), id); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete app", nil)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ChannelHandler handles channel-related API endpoints.
type ChannelHandler struct {
	DB *db.DB
}

// GetChannels handles GET /api/v1/apps/{appId}/channels
func (h *ChannelHandler) GetChannels(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appId")
	id, err := parseUUID(appID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid app ID", nil)
		return
	}

	channels, err := h.DB.GetChannelsByAppID(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch channels", nil)
		return
	}

	var result []models.Channel
	for _, c := range channels {
		result = append(result, models.Channel{
			ID:    c.ID,
			AppID: c.AppID,
			Name:  c.Name,
		})
	}

	respondJSON(w, http.StatusOK, result)
}

// CreateChannel handles POST /api/v1/apps/{appId}/channels
func (h *ChannelHandler) CreateChannel(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appId")
	id, err := parseUUID(appID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid app ID", nil)
		return
	}

	var req models.CreateChannelRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}

	channel, err := h.DB.CreateChannel(r.Context(), id, req.Channel)
	if err != nil {
		respondError(w, http.StatusConflict, "Channel already exists", strPtr(err.Error()))
		return
	}

	respondJSON(w, http.StatusCreated, models.Channel{
		ID:    channel.ID,
		AppID: channel.AppID,
		Name:  channel.Name,
	})
}

// OrganizationHandler handles organization-related API endpoints.
type OrganizationHandler struct {
	DB *db.DB
}

// GetOrganizations handles GET /api/v1/organizations
func (h *OrganizationHandler) GetOrganizations(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		respondError(w, http.StatusUnauthorized, "Unauthorized", nil)
		return
	}

	orgs, err := h.DB.GetOrganizationsByUserID(r.Context(), claims.UserID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch organizations", nil)
		return
	}

	var result []models.OrganizationMembership
	for _, o := range orgs {
		result = append(result, models.OrganizationMembership{
			Organization: models.Organization{
				ID:   o.OrgID,
				Name: o.OrgName,
				Type: o.OrgType,
			},
			Role: o.Role,
		})
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{"organizations": result})
}
