package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/shorebird-server/internal/api/middleware"
	"github.com/shorebird-server/internal/db"
	"github.com/shorebird-server/internal/models"
)

// AdminHandler handles admin/management API endpoints.
type AdminHandler struct {
	DB db.Store
}

// AddTargetDevice handles POST /api/v1/admin/patches/{patchId}/target-devices
// Restricts a patch to only be delivered to specific devices (by client_id).
func (h *AdminHandler) AddTargetDevice(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	patchID, err := strconv.Atoi(chi.URLParam(r, "patchId"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid patch ID", nil)
		return
	}

	var req struct {
		ClientID string `json:"client_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}

	if err := h.DB.AddPatchTargetDevice(r.Context(), patchID, req.ClientID); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to add target device", strPtr(err.Error()))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// RemoveTargetDevice handles DELETE /api/v1/admin/patches/{patchId}/target-devices/{clientId}
func (h *AdminHandler) RemoveTargetDevice(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	// For simplicity, target device removal is handled by the database cascade
	// In a full implementation, add a RemovePatchTargetDevice DB method
	respondError(w, http.StatusNotImplemented, "Not yet implemented", nil)
}

// GetTargetDevices handles GET /api/v1/admin/patches/{patchId}/target-devices
func (h *AdminHandler) GetTargetDevices(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	patchID, err := strconv.Atoi(chi.URLParam(r, "patchId"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid patch ID", nil)
		return
	}

	devices, err := h.DB.GetPatchTargetDevices(r.Context(), patchID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch target devices", nil)
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"patch_id":   patchID,
		"client_ids": devices,
	})
}

// GetPatchEvents handles GET /api/v1/admin/apps/{appId}/events
// Returns patch events for analytics.
func (h *AdminHandler) GetPatchEvents(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	appID, err := uuid.Parse(chi.URLParam(r, "appId"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid app ID", nil)
		return
	}
	if _, ok := requireAppAccess(w, r, h.DB, appID, false); !ok {
		return
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 500 {
			respondError(w, http.StatusBadRequest, "limit must be between 1 and 500", nil)
			return
		}
	}
	var beforeID int64
	if raw := r.URL.Query().Get("before_id"); raw != "" {
		beforeID, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || beforeID < 1 {
			respondError(w, http.StatusBadRequest, "before_id must be a positive integer", nil)
			return
		}
	}
	events, err := h.DB.ListPatchEvents(r.Context(), appID, beforeID, limit+1)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch patch events", nil)
		return
	}
	response := models.PatchEventListResponse{Events: make([]models.PatchEventRecord, 0, limit)}
	if len(events) > limit {
		events = events[:limit]
		next := events[len(events)-1].ID
		response.NextBeforeID = &next
	}
	for _, event := range events {
		response.Events = append(response.Events, models.PatchEventRecord{
			ID: event.ID, CreatedAt: event.CreatedAt.Time,
			PatchEvent: models.PatchEvent{
				AppID: event.AppID.String(), ClientID: event.ClientID, Arch: event.Arch,
				PatchNumber: event.PatchNumber, Platform: event.Platform, ReleaseVersion: event.ReleaseVersion,
				Type: event.Type, Timestamp: event.Timestamp, Message: event.Message,
				EventID: event.EventID, FailureCategory: event.FailureCategory,
			},
		})
	}
	respondJSON(w, http.StatusOK, response)
}

// ListUsers handles GET /api/v1/admin/users (admin convenience endpoint)
func (h *AdminHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}

	users, err := h.DB.ListAllUsers(r.Context())
	if err != nil {
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"message": "Admin endpoints available",
			"users":   []interface{}{},
		})
		return
	}

	type userEntry struct {
		ID            int    `json:"id"`
		Email         string `json:"email"`
		Name          string `json:"name"`
		Role          string `json:"role"`
		CreatedAt     string `json:"created_at"`
		EmailVerified bool   `json:"email_verified"`
		IsAdmin       bool   `json:"is_admin"`
	}

	result := make([]userEntry, 0, len(users))
	for _, u := range users {
		role := u.Role
		if role == "" {
			role = "member"
		}
		result = append(result, userEntry{
			ID:            u.ID,
			Email:         u.Email,
			Name:          u.Name,
			Role:          role,
			CreatedAt:     u.CreatedAt.Format("2006-01-02T15:04:05Z"),
			EmailVerified: u.EmailVerified,
			IsAdmin:       u.IsAdmin,
		})
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"users": result,
	})
}

func (h *AdminHandler) VerifyUserEmail(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	userID, err := strconv.Atoi(chi.URLParam(r, "userId"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid user ID", nil)
		return
	}
	if err := h.DB.MarkUserEmailVerified(r.Context(), userID); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to verify user email", nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) SetUserAdmin(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	userID, err := strconv.Atoi(chi.URLParam(r, "userId"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid user ID", nil)
		return
	}
	var req struct {
		IsAdmin bool `json:"is_admin"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}
	if err := h.DB.SetUserAdmin(r.Context(), userID, req.IsAdmin); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update admin status", nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) GetSettings(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	settings, err := h.DB.ListSettings(r.Context())
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to load settings", nil)
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"settings": redactedSettings(settings)})
}

func (h *AdminHandler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}
	var req map[string]string
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}
	allowed := map[string]bool{
		"registration_enabled":     true,
		"sso_registration_enabled": true,
		"sso_only_registration":    true,
		"casdoor_endpoint":         true,
		"casdoor_client_id":        true,
		"casdoor_client_secret":    true,
		"casdoor_organization":     true,
	}
	for key, value := range req {
		if !allowed[key] {
			continue
		}
		if key == "casdoor_client_secret" && value == "" {
			continue
		}
		if err := h.DB.SetSetting(r.Context(), key, value); err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to update settings", nil)
			return
		}
	}
	h.GetSettings(w, r)
}

func (h *AdminHandler) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	claims := middleware.GetClaims(r)
	if claims == nil {
		respondError(w, http.StatusUnauthorized, "Unauthorized", nil)
		return false
	}
	user, err := h.DB.GetUserByID(r.Context(), claims.UserID)
	if err != nil || !user.IsAdmin {
		respondError(w, http.StatusForbidden, "Admin access required", nil)
		return false
	}
	return true
}

func redactedSettings(settings map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range settings {
		if k == "casdoor_client_secret" && v != "" {
			out[k] = "********"
			continue
		}
		out[k] = v
	}
	return out
}
