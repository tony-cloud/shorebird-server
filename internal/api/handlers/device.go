package handlers

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/shorebird-server/internal/db"
	"github.com/shorebird-server/internal/models"
	"github.com/shorebird-server/internal/storage"
)

// DeviceHandler handles device-facing API endpoints (no auth required).
type DeviceHandler struct {
	DB      *db.DB
	Storage *storage.Service
}

// PatchCheck handles POST /api/v1/patches/check
// This is THE critical endpoint called by the device-side updater library.
// No authentication required.
func (h *DeviceHandler) PatchCheck(w http.ResponseWriter, r *http.Request) {
	var req models.PatchCheckRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}

	// Parse app ID
	appID, err := uuid.Parse(req.AppID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid app_id", nil)
		return
	}

	// Verify app exists
	_, err = h.DB.GetAppByID(r.Context(), appID)
	if err != nil {
		respondError(w, http.StatusNotFound, "App not found", nil)
		return
	}

	// Find the release by app and version
	release, err := h.DB.GetReleaseByAppIDAndVersion(r.Context(), appID, req.ReleaseVersion)
	if err != nil {
		// Release not found, no patch available
		respondJSON(w, http.StatusOK, models.PatchCheckResponse{
			PatchAvailable: false,
			RolledBackPatchNumbers: []int{},
		})
		return
	}

	// Get rolled back patches
	rolledBack, err := h.DB.GetRolledBackPatchNumbers(r.Context(), release.ID)
	if err != nil {
		rolledBack = []int{}
	}

	// Find the channel (default to "stable")
	channelName := req.Channel
	if channelName == "" {
		channelName = "stable"
	}

	channel, err := h.DB.GetChannelByAppIDAndName(r.Context(), appID, channelName)
	if err != nil {
		// Channel not found, no patch available
		respondJSON(w, http.StatusOK, models.PatchCheckResponse{
			PatchAvailable:         false,
			RolledBackPatchNumbers: rolledBack,
		})
		return
	}

	// Find the latest promoted patch for this release+channel
	patch, err := h.DB.GetLatestPromotedPatch(r.Context(), release.ID, channel.ID)
	if err != nil {
		// No patch available
		respondJSON(w, http.StatusOK, models.PatchCheckResponse{
			PatchAvailable:         false,
			RolledBackPatchNumbers: rolledBack,
		})
		return
	}

	// If the device already has this or a newer patch, no update needed
	if req.CurrentPatchNumber != nil && *req.CurrentPatchNumber >= patch.Number {
		respondJSON(w, http.StatusOK, models.PatchCheckResponse{
			PatchAvailable:         false,
			RolledBackPatchNumbers: rolledBack,
		})
		return
	}

	// Also check legacy patch_number field
	if req.PatchNumber != nil && *req.PatchNumber >= patch.Number {
		respondJSON(w, http.StatusOK, models.PatchCheckResponse{
			PatchAvailable:         false,
			RolledBackPatchNumbers: rolledBack,
		})
		return
	}

	// Check if this patch has targeted device restrictions
	if req.ClientID != nil {
		hasTargets, err := h.DB.HasTargetDevices(r.Context(), patch.ID)
		if err == nil && hasTargets {
			isTargeted, err := h.DB.IsPatchTargetedToDevice(r.Context(), patch.ID, *req.ClientID)
			if err != nil || !isTargeted {
				// Patch is restricted but this device is not in the allowlist
				respondJSON(w, http.StatusOK, models.PatchCheckResponse{
					PatchAvailable:         false,
					RolledBackPatchNumbers: rolledBack,
				})
				return
			}
		}
	}

	// Generate the public download URL for the patch artifact
	downloadURL, err := h.Storage.GeneratePublicDownloadURL(r.Context(), patch.StorageKey)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to generate download URL", nil)
		return
	}

	respondJSON(w, http.StatusOK, models.PatchCheckResponse{
		PatchAvailable: true,
		Patch: &models.PatchCheckMetadata{
			Number:        patch.Number,
			DownloadURL:   downloadURL,
			Hash:          patch.Hash,
			HashSignature: patch.HashSignature,
		},
		RolledBackPatchNumbers: rolledBack,
	})
}

// PatchEvents handles POST /api/v1/patches/events
// Records patch install success/failure events from devices.
// No authentication required.
func (h *DeviceHandler) PatchEvents(w http.ResponseWriter, r *http.Request) {
	var req models.CreatePatchEventRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}

	appID, err := uuid.Parse(req.Event.AppID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid app_id", nil)
		return
	}

	// Validate event type
	eventType := req.Event.Type
	if eventType != models.EventPatchInstallSuccess && eventType != models.EventPatchInstallFailure {
		respondError(w, http.StatusBadRequest, "Invalid event type", nil)
		return
	}

	if err := h.DB.InsertPatchEvent(r.Context(),
		appID,
		req.Event.ClientID,
		req.Event.Arch,
		req.Event.Platform,
		req.Event.ReleaseVersion,
		eventType,
		req.Event.PatchNumber,
		req.Event.Timestamp,
		req.Event.Message,
	); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to record event", nil)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// RollbackPatch handles POST /api/v1/apps/{appId}/patches/rollback (admin endpoint)
func (h *DeviceHandler) RollbackPatch(w http.ResponseWriter, r *http.Request) {
	// This is an admin operation. For now, allow authenticated users.
	var req struct {
		ReleaseID   int `json:"release_id"`
		PatchNumber int `json:"patch_number"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}

	if err := h.DB.RollbackPatch(r.Context(), req.ReleaseID, req.PatchNumber); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to rollback patch", nil)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Diagnostics (optional stubs) ---

// DiagnosticsHandler handles diagnostics/speed test endpoints.
type DiagnosticsHandler struct{}

// GCPUploadSpeedTest handles GET /api/v1/diagnostics/gcp_upload
func (h *DiagnosticsHandler) GCPUploadSpeedTest(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{
		"upload_url": "https://example.com/speedtest-upload",
	})
}

// GCPDownloadSpeedTest handles GET /api/v1/diagnostics/gcp_download
func (h *DiagnosticsHandler) GCPDownloadSpeedTest(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{
		"download_url": "https://example.com/speedtest-download",
	})
}
