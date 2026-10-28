package handlers

import (
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/shorebird-server/internal/db"
	"github.com/shorebird-server/internal/models"
	"github.com/shorebird-server/internal/storage"
)

// PatchHandler handles patch-related API endpoints.
type PatchHandler struct {
	DB      db.Store
	Storage storage.Store
	Signing *SigningHandler
}

// CreatePatch handles POST /api/v1/apps/{appId}/patches
func (h *PatchHandler) CreatePatch(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appId")
	parsedAppID, err := uuid.Parse(appID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid app ID", nil)
		return
	}
	if _, ok := requireAppAccess(w, r, h.DB, parsedAppID, true); !ok {
		return
	}

	var req models.CreatePatchRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}

	// Validate release exists and belongs to this app
	release, err := h.DB.GetReleaseByID(r.Context(), req.ReleaseID)
	if err != nil {
		respondError(w, http.StatusNotFound, "Release not found", nil)
		return
	}
	if release.AppID.String() != appID {
		respondError(w, http.StatusNotFound, "Release not found for this app", nil)
		return
	}

	// Auto-increment patch number
	patchNum, err := h.DB.GetNextPatchNumber(r.Context(), req.ReleaseID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to determine patch number", nil)
		return
	}

	patch, err := h.DB.CreatePatch(r.Context(), req.ReleaseID, patchNum, nil)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create patch", strPtr(err.Error()))
		return
	}

	respondJSON(w, http.StatusCreated, models.Patch{
		ID:     patch.ID,
		Number: patch.Number,
		Notes:  patch.Notes,
	})
}

// CreatePatchArtifact handles POST /api/v1/apps/{appId}/patches/{patchId}/artifacts
func (h *PatchHandler) CreatePatchArtifact(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appId")
	parsedAppID, err := uuid.Parse(appID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid app ID", nil)
		return
	}
	if _, ok := requireAppAccess(w, r, h.DB, parsedAppID, true); !ok {
		return
	}
	patchID, err := strconv.Atoi(chi.URLParam(r, "patchId"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid patch ID", nil)
		return
	}

	// Parse multipart form
	if err := r.ParseMultipartForm(100 << 20); err != nil {
		respondError(w, http.StatusBadRequest, "Failed to parse multipart form", nil)
		return
	}

	arch := r.FormValue("arch")
	platform := r.FormValue("platform")
	hash := r.FormValue("hash")
	sizeStr := r.FormValue("size")
	hashSignature := r.FormValue("hash_signature")
	podfileLockHash := r.FormValue("podfile_lock_hash")
	offlineExpiresAtRaw := r.FormValue("offline_expires_at")

	size, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil || size <= 0 || size > maxStorageUploadBytes {
		respondError(w, http.StatusBadRequest, "Invalid artifact size", nil)
		return
	}
	var offlineExpiresAt *time.Time
	if offlineExpiresAtRaw != "" {
		parsed, err := time.Parse(time.RFC3339, offlineExpiresAtRaw)
		if err != nil {
			respondError(w, http.StatusBadRequest, "Invalid offline_expires_at", strPtr(err.Error()))
			return
		}
		utc := parsed.UTC()
		offlineExpiresAt = &utc
	}

	// Get the patch to verify it exists and get release info
	patch, err := h.DB.GetPatchByID(r.Context(), patchID)
	if err != nil {
		respondError(w, http.StatusNotFound, "Patch not found", nil)
		return
	}

	release, err := h.DB.GetReleaseByID(r.Context(), patch.ReleaseID)
	if err != nil {
		respondError(w, http.StatusNotFound, "Release not found", nil)
		return
	}
	if release.AppID != parsedAppID {
		respondError(w, http.StatusNotFound, "Patch not found for this app", nil)
		return
	}

	hash, hashSignature, ok := h.Signing.patchHashSignature(w, r, parsedAppID, release.ID, arch, platform, hash, hashSignature)
	if !ok {
		return
	}

	// Generate a storage key for the public bucket
	filename := "dlc.vmcode" // standard patch artifact name
	storageKey := storage.GeneratePatchStorageKey(appID, release.ID, patch.Number, platform, arch, filename)

	// Generate presigned upload URL (public bucket)
	uploadURL, err := h.Storage.GeneratePresignedUploadURL(r.Context(), storageKey, true, 30*time.Minute, size)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to generate upload URL", strPtr(err.Error()))
		return
	}

	// Create the artifact record
	var hs *string
	if hashSignature != "" {
		hs = &hashSignature
	}
	var phl *string
	if podfileLockHash != "" {
		phl = &podfileLockHash
	}

	artifact, err := h.DB.CreatePatchArtifact(r.Context(), patchID, arch, platform, hash, storageKey, size, hs, phl, offlineExpiresAt)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create artifact record", strPtr(err.Error()))
		return
	}

	var responseOfflineExpiresAt *time.Time
	if artifact.OfflineExpiresAt.Valid {
		responseOfflineExpiresAt = artifact.OfflineExpiresAt.Ptr()
	}
	respondJSON(w, http.StatusCreated, models.CreatePatchArtifactResponse{
		ID:               artifact.ID,
		PatchID:          artifact.PatchID,
		Arch:             artifact.Arch,
		Platform:         artifact.Platform,
		Hash:             artifact.Hash,
		Size:             artifact.Size,
		URL:              uploadURL,
		OfflineExpiresAt: responseOfflineExpiresAt,
	})
}

// GetPatches handles GET /api/v1/apps/{appId}/releases/{releaseId}/patches
func (h *PatchHandler) GetPatches(w http.ResponseWriter, r *http.Request) {
	appID, err := uuid.Parse(chi.URLParam(r, "appId"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid app ID", nil)
		return
	}
	if _, ok := requireAppAccess(w, r, h.DB, appID, false); !ok {
		return
	}
	releaseID, err := strconv.Atoi(chi.URLParam(r, "releaseId"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid release ID", nil)
		return
	}
	release, err := h.DB.GetReleaseByID(r.Context(), releaseID)
	if err != nil || release.AppID != appID {
		respondError(w, http.StatusNotFound, "Release not found for this app", nil)
		return
	}

	patches, err := h.DB.GetPatchesByReleaseID(r.Context(), releaseID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch patches", nil)
		return
	}

	rolledBack, err := h.DB.GetRolledBackPatchNumbers(r.Context(), releaseID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch rollback state", nil)
		return
	}
	channels, err := h.DB.GetChannelsByAppID(r.Context(), appID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch channels", nil)
		return
	}
	channelNames := map[int]string{}
	for _, channel := range channels {
		channelNames[channel.ID] = channel.Name
	}
	result := []map[string]interface{}{}
	seen := map[int]bool{}
	for _, p := range patches {
		if seen[p.ID] {
			continue
		}
		seen[p.ID] = true
		artifacts, err := h.DB.GetPatchArtifacts(r.Context(), p.ID)
		if err != nil {
			respondError(w, http.StatusInternalServerError, "Failed to fetch patch artifacts", nil)
			return
		}
		artifactJSON := []map[string]interface{}{}
		for _, a := range artifacts {
			artifactJSON = append(artifactJSON, map[string]interface{}{
				"id": a.ID, "patch_id": a.PatchID, "arch": a.Arch, "platform": a.Platform, "hash": a.Hash, "size": a.Size, "created_at": a.CreatedAt.Time,
			})
		}
		result = append(result, map[string]interface{}{
			"id": p.ID, "release_id": p.ReleaseID, "patch_id": p.ID, "patch_number": p.Number,
			"number": p.Number, "artifacts": artifactJSON, "is_rolled_back": slices.Contains(rolledBack, p.Number),
			"channel": channelNames[p.ChannelID], "notes": p.Notes, "created_at": p.CreatedAt.Time,
		})
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{"patches": result})
}

// PromotePatch handles POST /api/v1/apps/{appId}/patches/promote
func (h *PatchHandler) PromotePatch(w http.ResponseWriter, r *http.Request) {
	appID, err := uuid.Parse(chi.URLParam(r, "appId"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid app ID", nil)
		return
	}
	if _, ok := requireAppAccess(w, r, h.DB, appID, true); !ok {
		return
	}
	var req models.PromotePatchRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}
	if !h.patchBelongsToApp(w, r, req.PatchID, appID) {
		return
	}

	if err := h.DB.PromotePatch(r.Context(), req.PatchID, req.ChannelID); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to promote patch", nil)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// UpdatePatch handles PATCH /api/v1/apps/{appId}/patches/{patchId}
func (h *PatchHandler) UpdatePatch(w http.ResponseWriter, r *http.Request) {
	appID, err := uuid.Parse(chi.URLParam(r, "appId"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid app ID", nil)
		return
	}
	if _, ok := requireAppAccess(w, r, h.DB, appID, true); !ok {
		return
	}
	patchID, err := strconv.Atoi(chi.URLParam(r, "patchId"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid patch ID", nil)
		return
	}
	if !h.patchBelongsToApp(w, r, patchID, appID) {
		return
	}
	var req models.UpdatePatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}

	// For now, notes are the only updatable field on patches
	// This would require an additional DB method
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *PatchHandler) patchBelongsToApp(w http.ResponseWriter, r *http.Request, patchID int, appID uuid.UUID) bool {
	patch, err := h.DB.GetPatchByID(r.Context(), patchID)
	if err != nil {
		respondError(w, http.StatusNotFound, "Patch not found", nil)
		return false
	}
	release, err := h.DB.GetReleaseByID(r.Context(), patch.ReleaseID)
	if err != nil || release.AppID != appID {
		respondError(w, http.StatusNotFound, "Patch not found for this app", nil)
		return false
	}
	return true
}

// RollbackPatch and RollforwardPatch implement the CLI's release-scoped lifecycle.
func (h *PatchHandler) RollbackPatch(w http.ResponseWriter, r *http.Request) {
	h.setRolledBack(w, r, true)
}
func (h *PatchHandler) RollforwardPatch(w http.ResponseWriter, r *http.Request) {
	h.setRolledBack(w, r, false)
}
func (h *PatchHandler) setRolledBack(w http.ResponseWriter, r *http.Request, rolledBack bool) {
	appID, err := uuid.Parse(chi.URLParam(r, "appId"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid app ID", nil)
		return
	}
	if _, ok := requireAppAccess(w, r, h.DB, appID, true); !ok {
		return
	}
	releaseID, err := strconv.Atoi(chi.URLParam(r, "releaseId"))
	if err != nil || releaseID <= 0 {
		respondError(w, http.StatusBadRequest, "Invalid release ID", nil)
		return
	}
	patchID, err := strconv.Atoi(chi.URLParam(r, "patchId"))
	if err != nil || patchID <= 0 {
		respondError(w, http.StatusBadRequest, "Invalid patch ID", nil)
		return
	}
	release, err := h.DB.GetReleaseByID(r.Context(), releaseID)
	if err != nil || release.AppID != appID {
		respondError(w, http.StatusNotFound, "Release not found for this app", nil)
		return
	}
	patch, err := h.DB.GetPatchByID(r.Context(), patchID)
	if err != nil || patch.ReleaseID != releaseID {
		respondError(w, http.StatusNotFound, "Patch not found for this release", nil)
		return
	}
	changed, err := h.DB.SetPatchRolledBack(r.Context(), releaseID, patch.Number, rolledBack)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to change rollback state", nil)
		return
	}
	if !changed {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
