package handlers

import (
	"encoding/json"
	"net/http"
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

	size, _ := strconv.ParseInt(sizeStr, 10, 64)

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

	// Generate a storage key for the public bucket
	filename := "dlc.vmcode" // standard patch artifact name
	storageKey := storage.GeneratePatchStorageKey(appID, release.ID, patch.Number, platform, arch, filename)

	// Generate presigned upload URL (public bucket)
	uploadURL, err := h.Storage.GeneratePresignedUploadURL(r.Context(), storageKey, true, 30*time.Minute)
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

	artifact, err := h.DB.CreatePatchArtifact(r.Context(), patchID, arch, platform, hash, storageKey, size, hs, phl)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create artifact record", strPtr(err.Error()))
		return
	}

	respondJSON(w, http.StatusCreated, models.CreatePatchArtifactResponse{
		ID:       artifact.ID,
		PatchID:  artifact.PatchID,
		Arch:     artifact.Arch,
		Platform: artifact.Platform,
		Hash:     artifact.Hash,
		Size:     artifact.Size,
		URL:      uploadURL,
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

	type releasePatch struct {
		ID          int       `json:"id"`
		ReleaseID   int       `json:"release_id"`
		PatchID     int       `json:"patch_id"`
		PatchNumber int       `json:"patch_number"`
		CreatedAt   time.Time `json:"created_at"`
	}

	var result []releasePatch
	for _, p := range patches {
		result = append(result, releasePatch{
			ID:          p.ID,
			ReleaseID:   p.ReleaseID,
			PatchID:     p.ID,
			PatchNumber: p.Number,
			CreatedAt:   p.PromotedAt.Time,
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
