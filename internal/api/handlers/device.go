package handlers

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/shorebird-server/internal/api/middleware"
	"github.com/shorebird-server/internal/db"
	"github.com/shorebird-server/internal/models"
	"github.com/shorebird-server/internal/storage"
)

// DeviceHandler handles device-facing API endpoints (no auth required).
type DeviceHandler struct {
	DB            db.Store
	Storage       storage.Store
	PatchDelivery PatchDeliveryConfig
	Signing       *SigningHandler
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

	if req.Nonce != "" {
		nonce, err := uuid.Parse(req.Nonce)
		if err != nil || nonce.Version() != 4 {
			respondError(w, http.StatusBadRequest, "nonce must be a UUIDv4", nil)
			return
		}
	}

	if !h.validatePatchDeliveryRequest(w, req) {
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
	h.recordPatchCheckActivity(r, appID, req)

	// Find the release by app and version
	release, err := h.DB.GetReleaseByAppIDAndVersion(r.Context(), appID, req.ReleaseVersion)
	if err != nil {
		// Release not found, no patch available
		respondJSON(w, http.StatusOK, models.PatchCheckResponse{
			PatchAvailable:         false,
			RolledBackPatchNumbers: []int{},
		})
		return
	}

	// Get rolled back patches
	rolledBack, err := h.DB.GetRolledBackPatchNumbers(r.Context(), release.ID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch rollback state", nil)
		return
	}
	currentPatchNumber := requestPatchNumber(req)
	potentialRemoval := h.expiredInstalledPatchRemoval(r, release.ID, currentPatchNumber, req.Arch, req.Platform, time.Now().UTC())

	// Find the channel (default to "stable")
	channelName := req.Channel
	if channelName == "" {
		channelName = "stable"
	}

	channel, err := h.DB.GetChannelByAppIDAndName(r.Context(), appID, channelName)
	if err != nil {
		// Channel not found, no patch available
		h.respondNoPatch(w, r, req, release.ID, rolledBack, potentialRemoval)
		return
	}

	// Find the latest promoted patch for this release+channel
	patch, err := h.DB.GetLatestPromotedPatch(r.Context(), release.ID, channel.ID, req.Arch, req.Platform)
	if err != nil {
		// No patch available
		h.respondNoPatch(w, r, req, release.ID, rolledBack, potentialRemoval)
		return
	}
	if patchExpired(patch, time.Now().UTC()) {
		h.respondNoPatch(w, r, req, release.ID, rolledBack, potentialRemoval)
		return
	}

	// If the device already has this or a newer patch, no update needed
	if req.CurrentPatchNumber != nil && *req.CurrentPatchNumber >= patch.Number {
		h.respondNoPatch(w, r, req, release.ID, rolledBack, potentialRemoval)
		return
	}

	// Also check legacy patch_number field
	if req.PatchNumber != nil && *req.PatchNumber >= patch.Number {
		h.respondNoPatch(w, r, req, release.ID, rolledBack, potentialRemoval)
		return
	}

	// Check if this patch has targeted device restrictions
	if req.ClientID != nil {
		hasTargets, err := h.DB.HasTargetDevices(r.Context(), patch.ID)
		if err == nil && hasTargets {
			isTargeted, err := h.DB.IsPatchTargetedToDevice(r.Context(), patch.ID, *req.ClientID)
			if err != nil || !isTargeted {
				// Patch is restricted but this device is not in the allowlist
				h.respondNoPatch(w, r, req, release.ID, rolledBack, potentialRemoval)
				return
			}
		}
	}

	delivery, err := h.maybeEncryptedPatchDelivery(r.Context(), appID, release.ID, req, patch)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to prepare patch download", nil)
		return
	}

	h.respondPatchCheck(w, r, req, release.ID, models.PatchCheckResponse{
		PatchAvailable: true,
		Patch: &models.PatchCheckMetadata{
			Number:           patch.Number,
			DownloadURL:      delivery.downloadURL,
			Hash:             patch.Hash,
			HashSignature:    patch.HashSignature,
			OfflineExpiresAt: patch.OfflineExpiresAt.Ptr(),
			Encryption:       delivery.encryption,
		},
		RolledBackPatchNumbers: rolledBack,
	})
}

func (h *DeviceHandler) respondNoPatch(w http.ResponseWriter, r *http.Request, req models.PatchCheckRequest, releaseID int, rolledBack []int, removal *models.PatchRemoval) {
	if rolledBack == nil {
		rolledBack = []int{}
	}
	if removal != nil {
		rolledBack = appendPatchNumberOnce(rolledBack, removal.Number)
	}
	h.respondPatchCheck(w, r, req, releaseID, models.PatchCheckResponse{
		PatchAvailable:         false,
		RolledBackPatchNumbers: rolledBack,
		RemovePatch:            removal,
	})
}

func requestPatchNumber(req models.PatchCheckRequest) *int {
	if req.CurrentPatchNumber != nil {
		return req.CurrentPatchNumber
	}
	return req.PatchNumber
}

func (h *DeviceHandler) expiredInstalledPatchRemoval(r *http.Request, releaseID int, patchNumber *int, arch, platform string, now time.Time) *models.PatchRemoval {
	if patchNumber == nil || *patchNumber <= 0 {
		return nil
	}
	installed, err := h.DB.GetPatchByReleaseNumber(r.Context(), releaseID, *patchNumber, arch, platform)
	if err != nil || !patchExpired(installed, now) {
		return nil
	}
	return &models.PatchRemoval{
		Number:           *patchNumber,
		Reason:           "offline_expired",
		OfflineExpiresAt: installed.OfflineExpiresAt.Ptr(),
	}
}

func patchExpired(patch *db.PatchWithArtifactRow, now time.Time) bool {
	if patch == nil || !patch.OfflineExpiresAt.Valid {
		return false
	}
	return !now.UTC().Before(patch.OfflineExpiresAt.Time.Time.UTC())
}

func appendPatchNumberOnce(numbers []int, patchNumber int) []int {
	for _, existing := range numbers {
		if existing == patchNumber {
			return numbers
		}
	}
	return append(numbers, patchNumber)
}

func (h *DeviceHandler) recordPatchCheckActivity(r *http.Request, appID uuid.UUID, req models.PatchCheckRequest) {
	if req.ClientID == nil || *req.ClientID == "" {
		return
	}
	patchNumber := 0
	if req.CurrentPatchNumber != nil {
		patchNumber = *req.CurrentPatchNumber
	} else if req.PatchNumber != nil {
		patchNumber = *req.PatchNumber
	}
	_ = h.DB.InsertPatchEvent(
		r.Context(),
		appID,
		*req.ClientID,
		req.Arch,
		req.Platform,
		req.ReleaseVersion,
		"PatchCheck",
		patchNumber,
		time.Now().UTC().UnixMilli(),
		nil,
	)
}

// PatchEvents handles POST /api/v1/patches/events
// Records patch download, install, and failure events from devices.
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

	// Accept the updater's wire identifiers and normalize the two legacy
	// server-specific names so newly stored events share canonical identifiers.
	eventType := req.Event.Type
	switch eventType {
	case "PatchInstallSuccess":
		eventType = models.EventPatchInstallSuccess
	case "PatchInstallFailure":
		eventType = models.EventPatchInstallFailure
	case models.EventPatchInstallSuccess, models.EventPatchInstallFailure, models.EventPatchDownload, models.EventPatchUpdateFailure:
	default:
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
	claims := middleware.GetClaims(r)
	if claims == nil {
		respondError(w, http.StatusUnauthorized, "Unauthorized", nil)
		return
	}
	user, err := h.DB.GetUserByID(r.Context(), claims.UserID)
	if err != nil || !user.IsAdmin {
		respondError(w, http.StatusForbidden, "Admin access required", nil)
		return
	}

	var req struct {
		ReleaseID   int `json:"release_id"`
		PatchNumber int `json:"patch_number"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}

	appID, err := uuid.Parse(chi.URLParam(r, "appId"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid app ID", nil)
		return
	}
	release, err := h.DB.GetReleaseByID(r.Context(), req.ReleaseID)
	if err != nil || release.AppID != appID {
		respondError(w, http.StatusNotFound, "Release not found for this app", nil)
		return
	}
	patches, err := h.DB.GetPatchesByReleaseID(r.Context(), req.ReleaseID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch patches", nil)
		return
	}
	found := false
	for _, patch := range patches {
		if patch.Number == req.PatchNumber {
			found = true
			break
		}
	}
	if !found {
		respondError(w, http.StatusNotFound, "Patch not found for this release", nil)
		return
	}

	if err := h.DB.RollbackPatch(r.Context(), req.ReleaseID, req.PatchNumber); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to rollback patch", nil)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
