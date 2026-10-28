package handlers

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/shorebird-server/internal/models"
)

type signedPatchMetadata struct {
	Number        int     `json:"number"`
	Hash          string  `json:"hash"`
	DownloadURL   string  `json:"download_url"`
	HashSignature *string `json:"hash_signature"`
}
type signedPatchCheckPayload struct {
	Version                int                  `json:"version"`
	AppID                  string               `json:"app_id"`
	ReleaseVersion         string               `json:"release_version"`
	Platform               string               `json:"platform"`
	Arch                   string               `json:"arch"`
	Channel                string               `json:"channel"`
	Nonce                  string               `json:"nonce"`
	PatchAvailable         bool                 `json:"patch_available"`
	Patch                  *signedPatchMetadata `json:"patch"`
	RolledBackPatchNumbers []int                `json:"rolled_back_patch_numbers"`
}

// respondPatchCheck signs the control response for nonce-aware managed releases,
// including rollback-only and no-update responses. Legacy requests remain usable.
func (h *DeviceHandler) respondPatchCheck(w http.ResponseWriter, r *http.Request, req models.PatchCheckRequest, releaseID int, response models.PatchCheckResponse) {
	if response.RolledBackPatchNumbers == nil {
		response.RolledBackPatchNumbers = []int{}
	}
	if req.Nonce == "" {
		respondJSON(w, http.StatusOK, response)
		return
	}
	policy, err := h.Signing.resolveReleaseSigningPolicy(r.Context(), releaseID, req.Platform, req.Arch)
	if errors.Is(err, sql.ErrNoRows) {
		respondJSON(w, http.StatusOK, response)
		return
	}
	if err != nil {
		respondError(w, http.StatusConflict, "Release signing policy is inconsistent or unavailable", nil)
		return
	}
	if policy.SigningMode == nil || *policy.SigningMode != "managed" {
		respondJSON(w, http.StatusOK, response)
		return
	}

	if !h.Signing.available(w) {
		return
	}
	keyID := policy.SigningKeyID
	if keyID == nil {
		respondError(w, http.StatusConflict, "Managed release has no signing key", nil)
		return
	}
	key, err := h.DB.GetSigningKeyByID(r.Context(), *keyID)
	appID, parseErr := uuid.Parse(req.AppID)
	if err != nil || parseErr != nil || key.AppID != appID {
		respondError(w, http.StatusConflict, "Release signing key is unavailable", nil)
		return
	}
	payload := signedPatchCheckPayload{
		Version: 1, AppID: req.AppID, ReleaseVersion: req.ReleaseVersion, Platform: req.Platform, Arch: req.Arch, Channel: req.Channel, Nonce: req.Nonce,
		PatchAvailable: response.PatchAvailable, RolledBackPatchNumbers: response.RolledBackPatchNumbers,
	}
	if response.Patch != nil {
		payload.Patch = &signedPatchMetadata{Number: response.Patch.Number, Hash: response.Patch.Hash, DownloadURL: response.Patch.DownloadURL, HashSignature: response.Patch.HashSignature}
	}
	serialized, err := json.Marshal(payload)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to encode authenticated patch response", nil)
		return
	}
	signature, err := h.Signing.signMessage(key, serialized)
	if err != nil {
		respondCodedError(w, http.StatusServiceUnavailable, "managed_signing_unavailable", "Failed to sign patch response")
		return
	}
	response.Authentication = &models.PatchResponseAuthentication{Payload: base64.StdEncoding.EncodeToString(serialized), Signature: signature}
	respondJSON(w, http.StatusOK, response)
}
