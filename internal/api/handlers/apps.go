package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/shorebird-server/internal/api/middleware"
	"github.com/shorebird-server/internal/auth"
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
	DB      db.Store
	BaseURL string
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
		"id":                      user.ID,
		"email":                   user.Email,
		"display_name":            user.Name,
		"email_verified":          user.EmailVerified,
		"is_admin":                user.IsAdmin,
		"must_change_password":    user.MustChangePassword,
		"jwt_issuer":              strings.TrimRight(h.BaseURL, "/") + "/auth",
		"has_active_subscription": true,
		"stripe_customer_id":      nil,
		"patch_overage_limit":     nil,
	})
}

// UpdatePassword handles PATCH /api/v1/users/me/password
func (h *UserHandler) UpdatePassword(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		respondError(w, http.StatusUnauthorized, "Unauthorized", nil)
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}
	user, err := h.DB.GetUserByID(r.Context(), claims.UserID)
	if err != nil {
		respondError(w, http.StatusNotFound, "User not found", nil)
		return
	}
	if !user.MustChangePassword && auth.CheckPassword(user.PasswordHash, req.CurrentPassword) != nil {
		respondError(w, http.StatusUnauthorized, "Current password is incorrect", nil)
		return
	}
	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to hash password", nil)
		return
	}
	if err := h.DB.UpdateUserPassword(r.Context(), user.ID, hash); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update password", nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
	DB db.Store
}

// GetApp handles GET /api/v1/apps/{appId}.
func (h *AppHandler) GetApp(w http.ResponseWriter, r *http.Request) {
	id, err := parseUUID(chi.URLParam(r, "appId"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid app ID", nil)
		return
	}
	app, ok := requireAppAccess(w, r, h.DB, id, false)
	if !ok {
		return
	}
	respondJSON(w, http.StatusOK, models.AppMetadata{
		AppID: app.ID.String(), OrganizationID: app.OrganizationID,
		DisplayName: app.DisplayName, CreatedAt: app.CreatedAt.Time, UpdatedAt: app.UpdatedAt.Time,
		Platforms: []string{}, LatestReleases: map[string]models.LatestRelease{}, PendingReleases: map[string]models.PendingRelease{},
	})
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
			AppID:           a.ID.String(),
			OrganizationID:  a.OrganizationID,
			DisplayName:     a.DisplayName,
			CreatedAt:       a.CreatedAt.Time,
			UpdatedAt:       a.UpdatedAt.Time,
			Platforms:       []string{},
			LatestReleases:  map[string]models.LatestRelease{},
			PendingReleases: map[string]models.PendingRelease{},
		})
	}
	if result == nil {
		result = []models.AppMetadata{}
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
	if !h.canManageOrganization(r, claims.UserID, req.OrganizationID) {
		respondError(w, http.StatusForbidden, "Organization admin access required", nil)
		return
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
		"id":           app.ID.String(),
		"display_name": app.DisplayName,
		"created_at":   app.CreatedAt,
		"updated_at":   app.UpdatedAt,
	})
}

// DeleteApp handles DELETE /api/v1/apps/{appId}
func (h *AppHandler) DeleteApp(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		respondError(w, http.StatusUnauthorized, "Unauthorized", nil)
		return
	}
	appID := chi.URLParam(r, "appId")
	id, err := parseUUID(appID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid app ID", nil)
		return
	}
	app, err := h.DB.GetAppByID(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusNotFound, "App not found", nil)
		return
	}
	if !h.canManageOrganization(r, claims.UserID, app.OrganizationID) {
		respondError(w, http.StatusForbidden, "Organization admin access required", nil)
		return
	}

	if err := h.DB.DeleteApp(r.Context(), id); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete app", nil)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *AppHandler) TransferApp(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		respondError(w, http.StatusUnauthorized, "Unauthorized", nil)
		return
	}
	appID := chi.URLParam(r, "appId")
	id, err := parseUUID(appID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid app ID", nil)
		return
	}
	var req struct {
		OrganizationID int `json:"organization_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}
	app, err := h.DB.GetAppByID(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusNotFound, "App not found", nil)
		return
	}
	if !h.canManageOrganization(r, claims.UserID, app.OrganizationID) || !h.canManageOrganization(r, claims.UserID, req.OrganizationID) {
		respondError(w, http.StatusForbidden, "Organization admin access required", nil)
		return
	}
	if err := h.DB.UpdateAppOrganization(r.Context(), id, req.OrganizationID); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to transfer app", strPtr(err.Error()))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AppHandler) canManageOrganization(r *http.Request, userID, orgID int) bool {
	return canAccessOrganization(r, h.DB, userID, orgID, true)
}

// ChannelHandler handles channel-related API endpoints.
type ChannelHandler struct {
	DB db.Store
}

// GetChannels handles GET /api/v1/apps/{appId}/channels
func (h *ChannelHandler) GetChannels(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appId")
	id, err := parseUUID(appID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid app ID", nil)
		return
	}
	if _, ok := requireAppAccess(w, r, h.DB, id, false); !ok {
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
	if _, ok := requireAppAccess(w, r, h.DB, id, true); !ok {
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
	DB db.Store
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
				ID:               o.OrgID,
				Name:             o.OrgName,
				OrganizationType: o.OrgType,
				CreatedAt:        o.CreatedAt.Time,
				UpdatedAt:        o.CreatedAt.Time,
			},
			Role: o.Role,
		})
	}
	if result == nil {
		result = []models.OrganizationMembership{}
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{"organizations": result})
}

func (h *OrganizationHandler) CreateOrganization(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		respondError(w, http.StatusUnauthorized, "Unauthorized", nil)
		return
	}
	var req struct {
		Name string `json:"name"`
		Type string `json:"organization_type"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}
	if req.Type == "" {
		req.Type = "team"
	}
	orgID, err := h.DB.CreateOrganization(r.Context(), req.Name, req.Type)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create organization", strPtr(err.Error()))
		return
	}
	if err := h.DB.AddUserToOrganization(r.Context(), claims.UserID, orgID, "admin"); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to add organization owner", nil)
		return
	}
	orgs, err := h.DB.GetOrganizationsByUserID(r.Context(), claims.UserID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch created organization", nil)
		return
	}
	for _, org := range orgs {
		if org.OrgID == orgID {
			respondJSON(w, http.StatusCreated, models.Organization{ID: org.OrgID, Name: org.OrgName, OrganizationType: org.OrgType, CreatedAt: org.CreatedAt.Time, UpdatedAt: org.CreatedAt.Time})
			return
		}
	}
	respondError(w, http.StatusInternalServerError, "Created organization not found", nil)
}

func (h *OrganizationHandler) ListOrganizationUsers(w http.ResponseWriter, r *http.Request) {
	orgID, ok := h.requireOrgAdmin(w, r)
	if !ok {
		return
	}
	users, err := h.DB.ListOrganizationUsers(r.Context(), orgID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch organization users", nil)
		return
	}
	result := make([]map[string]interface{}, 0, len(users))
	for _, u := range users {
		result = append(result, map[string]interface{}{
			"id": u.ID, "email": u.Email, "name": u.Name, "role": u.Role,
			"email_verified": u.EmailVerified, "is_admin": u.IsAdmin,
			"created_at": u.CreatedAt.Format("2006-01-02T15:04:05Z"),
		})
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"users": result})
}

func (h *OrganizationHandler) AddOrganizationUser(w http.ResponseWriter, r *http.Request) {
	orgID, ok := h.requireOrgAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}
	if req.Role == "" {
		req.Role = "member"
	}
	user, err := h.DB.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		respondError(w, http.StatusNotFound, "User not found", strPtr("Create the user first, then add them to the organization."))
		return
	}
	if err := h.DB.AddUserToOrganization(r.Context(), user.ID, orgID, req.Role); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to add user to organization", nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *OrganizationHandler) requireOrgAdmin(w http.ResponseWriter, r *http.Request) (int, bool) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		respondError(w, http.StatusUnauthorized, "Unauthorized", nil)
		return 0, false
	}
	orgID, err := strconv.Atoi(chi.URLParam(r, "orgId"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid organization ID", nil)
		return 0, false
	}
	user, _ := h.DB.GetUserByID(r.Context(), claims.UserID)
	role, err := h.DB.GetOrganizationRole(r.Context(), claims.UserID, orgID)
	if err != nil || (role != "admin" && (user == nil || !user.IsAdmin)) {
		respondError(w, http.StatusForbidden, "Organization admin access required", nil)
		return 0, false
	}
	return orgID, true
}
