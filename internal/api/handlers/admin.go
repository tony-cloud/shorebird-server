package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/shorebird-server/internal/api/middleware"
	"github.com/shorebird-server/internal/db"
)

// AdminHandler handles admin/management API endpoints.
type AdminHandler struct {
	DB db.Store
}

// AddTargetDevice handles POST /api/v1/admin/patches/{patchId}/target-devices
// Restricts a patch to only be delivered to specific devices (by client_id).
func (h *AdminHandler) AddTargetDevice(w http.ResponseWriter, r *http.Request) {
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
	// For simplicity, target device removal is handled by the database cascade
	// In a full implementation, add a RemovePatchTargetDevice DB method
	respondError(w, http.StatusNotImplemented, "Not yet implemented", nil)
}

// GetTargetDevices handles GET /api/v1/admin/patches/{patchId}/target-devices
func (h *AdminHandler) GetTargetDevices(w http.ResponseWriter, r *http.Request) {
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
		"patch_id":     patchID,
		"client_ids":   devices,
	})
}

// GetPatchEvents handles GET /api/v1/admin/apps/{appId}/events
// Returns patch events for analytics.
func (h *AdminHandler) GetPatchEvents(w http.ResponseWriter, r *http.Request) {
	// This would query patch_events table for the app
	// For now, return a stub
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"events": []map[string]interface{}{},
	})
}

// ListUsers handles GET /api/v1/admin/users (admin convenience endpoint)
func (h *AdminHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		respondError(w, http.StatusUnauthorized, "Unauthorized", nil)
		return
	}

	users, err := h.DB.ListAllUsers(r.Context())
	if err != nil {
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"message": "Admin endpoints available",
			"user":    claims.Email,
			"users":   []interface{}{},
		})
		return
	}

	type userEntry struct {
		ID        int    `json:"id"`
		Email     string `json:"email"`
		Name      string `json:"name"`
		Role      string `json:"role"`
		CreatedAt string `json:"created_at"`
	}

	result := make([]userEntry, 0, len(users))
	for _, u := range users {
		role := u.Role
		if role == "" {
			role = "member"
		}
		result = append(result, userEntry{
			ID:        u.ID,
			Email:     u.Email,
			Name:      u.Name,
			Role:      role,
			CreatedAt: u.CreatedAt.Format("2006-01-02T15:04:05Z"),
		})
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"users": result,
	})
}
