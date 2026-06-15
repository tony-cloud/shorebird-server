package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/shorebird-server/internal/db"
	"github.com/shorebird-server/internal/models"
	"github.com/shorebird-server/internal/storage"
)

// parseUUID parses a UUID string.
func parseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}

// parseIntParam parses an integer URL parameter.
func parseIntParam(r *http.Request, name string) (int, error) {
	return strconv.Atoi(chi.URLParam(r, name))
}

// ReleaseHandler handles release-related API endpoints.
type ReleaseHandler struct {
	DB      db.Store
	Storage storage.Store
	BaseURL string
}

// GetReleases handles GET /api/v1/apps/{appId}/releases
func (h *ReleaseHandler) GetReleases(w http.ResponseWriter, r *http.Request) {
	appID, err := parseUUID(chi.URLParam(r, "appId"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid app ID", nil)
		return
	}
	if _, ok := requireAppAccess(w, r, h.DB, appID, false); !ok {
		return
	}

	sideloadable := r.URL.Query().Get("sideloadable") == "true"

	releases, err := h.DB.GetReleasesByAppID(r.Context(), appID, sideloadable)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch releases", nil)
		return
	}

	var result []models.Release
	for _, rel := range releases {
		statuses, _ := h.DB.GetReleasePlatformStatuses(r.Context(), rel.ID)
		if statuses == nil {
			statuses = map[string]string{}
		}

		result = append(result, models.Release{
			ID:               rel.ID,
			AppID:            rel.AppID,
			Version:          rel.Version,
			FlutterRevision:  rel.FlutterRevision,
			FlutterVersion:   rel.FlutterVersion,
			DisplayName:      rel.DisplayName,
			Notes:            rel.Notes,
			PlatformStatuses: statuses,
			CreatedAt:        rel.CreatedAt.Time,
			UpdatedAt:        rel.UpdatedAt.Time,
		})
	}
	if result == nil {
		result = []models.Release{}
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{"releases": result})
}

// CreateRelease handles POST /api/v1/apps/{appId}/releases
func (h *ReleaseHandler) CreateRelease(w http.ResponseWriter, r *http.Request) {
	appID, err := parseUUID(chi.URLParam(r, "appId"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid app ID", nil)
		return
	}
	if _, ok := requireAppAccess(w, r, h.DB, appID, true); !ok {
		return
	}

	var req models.CreateReleaseRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}

	release, err := h.DB.CreateRelease(r.Context(), appID, req.Version, req.FlutterRevision, req.FlutterVersion, req.DisplayName)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create release", strPtr(err.Error()))
		return
	}

	respondJSON(w, http.StatusCreated, models.CreateReleaseResponse{
		Release: models.Release{
			ID:               release.ID,
			AppID:            release.AppID,
			Version:          release.Version,
			FlutterRevision:  release.FlutterRevision,
			FlutterVersion:   release.FlutterVersion,
			DisplayName:      release.DisplayName,
			Notes:            release.Notes,
			PlatformStatuses: map[string]string{},
			CreatedAt:        release.CreatedAt.Time,
			UpdatedAt:        release.UpdatedAt.Time,
		},
	})
}

// UpdateRelease handles PATCH /api/v1/apps/{appId}/releases/{releaseId}
func (h *ReleaseHandler) UpdateRelease(w http.ResponseWriter, r *http.Request) {
	appID, err := parseUUID(chi.URLParam(r, "appId"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid app ID", nil)
		return
	}
	if _, ok := requireAppAccess(w, r, h.DB, appID, true); !ok {
		return
	}
	releaseID, err := parseIntParam(r, "releaseId")
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid release ID", nil)
		return
	}
	if !h.releaseBelongsToApp(w, r, releaseID, appID) {
		return
	}

	var req models.UpdateReleaseRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid request body", nil)
		return
	}

	if err := h.DB.UpdateReleasePlatformStatus(r.Context(), releaseID, req.Platform, req.Status, req.Metadata); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to update release", nil)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *ReleaseHandler) DeleteRelease(w http.ResponseWriter, r *http.Request) {
	appID, err := parseUUID(chi.URLParam(r, "appId"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid app ID", nil)
		return
	}
	if _, ok := requireAppAccess(w, r, h.DB, appID, true); !ok {
		return
	}
	releaseID, err := parseIntParam(r, "releaseId")
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid release ID", nil)
		return
	}
	if !h.releaseBelongsToApp(w, r, releaseID, appID) {
		return
	}
	if err := h.DB.DeleteRelease(r.Context(), releaseID); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to delete release", strPtr(err.Error()))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// CreateReleaseArtifact handles POST /api/v1/apps/{appId}/releases/{releaseId}/artifacts
func (h *ReleaseHandler) CreateReleaseArtifact(w http.ResponseWriter, r *http.Request) {
	appID := chi.URLParam(r, "appId")
	parsedAppID, err := parseUUID(appID)
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid app ID", nil)
		return
	}
	if _, ok := requireAppAccess(w, r, h.DB, parsedAppID, true); !ok {
		return
	}
	releaseID, err := parseIntParam(r, "releaseId")
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid release ID", nil)
		return
	}
	if !h.releaseBelongsToApp(w, r, releaseID, parsedAppID) {
		return
	}

	// The CLI sends multipart form data. Parse it.
	if err := r.ParseMultipartForm(100 << 20); err != nil { // 100MB max
		respondError(w, http.StatusBadRequest, "Failed to parse multipart form", nil)
		return
	}

	arch := r.FormValue("arch")
	platform := r.FormValue("platform")
	hash := r.FormValue("hash")
	sizeStr := r.FormValue("size")
	canSideloadStr := r.FormValue("can_sideload")
	filename := r.FormValue("filename")
	podfileLockHash := r.FormValue("podfile_lock_hash")

	size, _ := strconv.ParseInt(sizeStr, 10, 64)
	canSideload := canSideloadStr == "true"

	// Get the release to know its version
	release, err := h.DB.GetReleaseByID(r.Context(), releaseID)
	if err != nil {
		respondError(w, http.StatusNotFound, "Release not found", nil)
		return
	}

	// Generate a storage key
	storageKey := storage.GenerateReleaseStorageKey(appID, release.Version, platform, arch, filename)

	// Generate presigned upload URL
	uploadURL, err := h.Storage.GeneratePresignedUploadURL(r.Context(), storageKey, false, 30*time.Minute)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to generate upload URL", strPtr(err.Error()))
		return
	}

	// Create the artifact record in DB
	var phl *string
	if podfileLockHash != "" {
		phl = &podfileLockHash
	}

	artifact, err := h.DB.CreateReleaseArtifact(r.Context(), releaseID, arch, platform, hash, storageKey, size, canSideload, phl)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to create artifact record", strPtr(err.Error()))
		return
	}

	respondJSON(w, http.StatusCreated, models.CreateReleaseArtifactResponse{
		ID:              artifact.ID,
		ReleaseID:       artifact.ReleaseID,
		Arch:            artifact.Arch,
		Platform:        artifact.Platform,
		Hash:            artifact.Hash,
		Size:            artifact.Size,
		URL:             uploadURL,
		CreatedAt:       artifact.CreatedAt.Time,
		CanSideload:     artifact.CanSideload,
		PodfileLockHash: artifact.PodfileLockHash,
	})
}

// GetReleaseArtifacts handles GET /api/v1/apps/{appId}/releases/{releaseId}/artifacts
func (h *ReleaseHandler) GetReleaseArtifacts(w http.ResponseWriter, r *http.Request) {
	appID, err := parseUUID(chi.URLParam(r, "appId"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid app ID", nil)
		return
	}
	if _, ok := requireAppAccess(w, r, h.DB, appID, false); !ok {
		return
	}
	releaseID, err := parseIntParam(r, "releaseId")
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid release ID", nil)
		return
	}
	if !h.releaseBelongsToApp(w, r, releaseID, appID) {
		return
	}

	var archPtr, platformPtr *string
	if a := r.URL.Query().Get("arch"); a != "" {
		archPtr = &a
	}
	if p := r.URL.Query().Get("platform"); p != "" {
		platformPtr = &p
	}

	artifacts, err := h.DB.GetReleaseArtifacts(r.Context(), releaseID, archPtr, platformPtr)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to fetch artifacts", nil)
		return
	}

	var result []models.ReleaseArtifact
	for _, a := range artifacts {
		// Build a download URL for the artifact
		downloadURL := fmt.Sprintf("%s/storage/dl/releases/%s", strings.TrimRight(h.BaseURL, "/"), a.StorageKey)
		result = append(result, models.ReleaseArtifact{
			ID:              a.ID,
			ReleaseID:       a.ReleaseID,
			Arch:            a.Arch,
			Platform:        a.Platform,
			Hash:            a.Hash,
			Size:            a.Size,
			URL:             downloadURL,
			CanSideload:     a.CanSideload,
			PodfileLockHash: a.PodfileLockHash,
			CreatedAt:       a.CreatedAt.Time,
		})
	}

	if result == nil {
		result = []models.ReleaseArtifact{}
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{"artifacts": result})
}

func (h *ReleaseHandler) releaseBelongsToApp(w http.ResponseWriter, r *http.Request, releaseID int, appID uuid.UUID) bool {
	release, err := h.DB.GetReleaseByID(r.Context(), releaseID)
	if err != nil || release.AppID != appID {
		respondError(w, http.StatusNotFound, "Release not found for this app", nil)
		return false
	}
	return true
}
