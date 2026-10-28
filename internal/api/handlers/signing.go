package handlers

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/shorebird-server/internal/db"
	"github.com/shorebird-server/internal/models"
)

// SigningConfig holds the independent 32-byte key which wraps managed private keys.
// It must be backed up with the database; changing it requires a key migration.
type SigningConfig struct{ MasterKey []byte }

type SigningHandler struct {
	DB        db.Store
	MasterKey []byte
}

func (h *SigningHandler) available(w http.ResponseWriter) bool {
	if h == nil || len(h.MasterKey) != 32 {
		respondCodedError(w, http.StatusServiceUnavailable, "managed_signing_unavailable", "Managed signing requires PATCH_SIGNING_MASTER_KEY (base64-encoded 32 bytes)")
		return false
	}
	return true
}

// GetSigningKey returns the public half of an app's persistent managed key only.
func (h *SigningHandler) GetSigningKey(w http.ResponseWriter, r *http.Request) {
	appID, err := uuid.Parse(chi.URLParam(r, "appId"))
	if err != nil {
		respondError(w, http.StatusBadRequest, "Invalid app ID", nil)
		return
	}
	if _, ok := requireAppAccess(w, r, h.DB, appID, true); !ok {
		return
	}
	if !h.available(w) {
		return
	}
	key, err := h.DB.GetAppSigningKey(r.Context(), appID)
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		key, err = h.createKey(r.Context(), appID)
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to load managed signing key", nil)
		return
	}
	respondJSON(w, http.StatusOK, map[string]interface{}{"signing_key": map[string]interface{}{"id": key.ID, "public_key_pem": key.PublicKeyPEM}})
}

func (h *SigningHandler) createKey(ctx context.Context, appID uuid.UUID) (*db.SigningKeyRow, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	publicPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	defer clear(privateDER)
	gcm, err := h.wrappingCipher()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	wrapped := gcm.Seal(nonce, nonce, privateDER, signingKeyAAD(appID))
	return h.DB.CreateAppSigningKey(ctx, appID, publicPEM, base64.StdEncoding.EncodeToString(wrapped))
}
func (h *SigningHandler) wrappingCipher() (cipher.AEAD, error) {
	if len(h.MasterKey) != 32 {
		return nil, fmt.Errorf("managed signing key unavailable")
	}
	block, err := aes.NewCipher(h.MasterKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func signingKeyAAD(appID uuid.UUID) []byte {
	return []byte("shorebird-managed-signing-v1\napp_id=" + appID.String())
}

func (h *SigningHandler) signPatchHash(ctx context.Context, key *db.SigningKeyRow, hash string) (string, error) {
	// Match CodeSigner and updater: sign the UTF-8 lowercase hash string.
	return h.signMessage(key, []byte(hash))
}

func (h *SigningHandler) signMessage(key *db.SigningKeyRow, message []byte) (string, error) {
	gcm, err := h.wrappingCipher()
	if err != nil {
		return "", err
	}
	wrapped, err := base64.StdEncoding.DecodeString(key.WrappedPrivateKey)
	if err != nil {
		return "", err
	}
	if len(wrapped) < gcm.NonceSize()+gcm.Overhead() {
		return "", fmt.Errorf("invalid wrapped signing key")
	}
	nonce := wrapped[:gcm.NonceSize()]
	privateDER, err := gcm.Open(nil, nonce, wrapped[gcm.NonceSize():], signingKeyAAD(key.AppID))
	if err != nil {
		return "", err
	}
	defer clear(privateDER)
	parsed, err := x509.ParsePKCS8PrivateKey(privateDER)
	if err != nil {
		return "", err
	}
	privateKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("managed signing key is not RSA")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", err
	}
	if string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})) != key.PublicKeyPEM {
		return "", fmt.Errorf("managed signing public key mismatch")
	}
	digest := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

func (h *SigningHandler) parseReleaseSigning(w http.ResponseWriter, r *http.Request, appID uuid.UUID) (*db.ReleaseSigningPolicy, bool) {
	raw := r.FormValue("signing")
	if raw == "" {
		return nil, true
	} // Legacy releases retain their existing behavior.
	var req struct {
		Mode  string `json:"mode"`
		KeyID *int   `json:"key_id"`
	}
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		respondError(w, http.StatusBadRequest, "Invalid signing metadata", nil)
		return nil, false
	}
	switch req.Mode {
	case "managed":
		if !h.available(w) {
			return nil, false
		}
		if req.KeyID == nil || *req.KeyID <= 0 {
			respondError(w, http.StatusBadRequest, "Managed signing requires key_id", nil)
			return nil, false
		}
		key, err := h.DB.GetSigningKeyByID(r.Context(), *req.KeyID)
		if err != nil || key.AppID != appID {
			respondError(w, http.StatusBadRequest, "Signing key does not belong to this app", nil)
			return nil, false
		}
	case "customer", "unsigned":
		if req.KeyID != nil {
			respondError(w, http.StatusBadRequest, "key_id is only valid for managed signing", nil)
			return nil, false
		}
	default:
		respondError(w, http.StatusBadRequest, "Unknown signing mode", nil)
		return nil, false
	}
	return &db.ReleaseSigningPolicy{Mode: req.Mode, KeyID: req.KeyID}, true
}

func (h *SigningHandler) artifactSigning(ctx context.Context, appID uuid.UUID, artifact db.ArtifactRow) (*models.ArtifactSigning, error) {
	if artifact.SigningMode == nil {
		return nil, nil
	}
	policy := &models.ArtifactSigning{Mode: *artifact.SigningMode, KeyID: artifact.SigningKeyID}
	if policy.Mode == "managed" {
		if policy.KeyID == nil {
			return nil, fmt.Errorf("managed release has no signing key")
		}
		key, err := h.DB.GetSigningKeyByID(ctx, *policy.KeyID)
		if err != nil {
			return nil, err
		}
		if key.AppID != appID {
			return nil, fmt.Errorf("release signing key belongs to another app")
		}
		policy.PublicKeyPEM = &key.PublicKeyPEM
	}
	return policy, nil
}

// patchHashSignature inherits its policy from the baseline, never the patch request.
func (h *SigningHandler) patchHashSignature(w http.ResponseWriter, r *http.Request, appID uuid.UUID, releaseID int, arch, platform, hash, providedSignature string) (string, string, bool) {
	if r.FormValue("signing") != "" {
		respondError(w, http.StatusBadRequest, "Patch signing policy is inherited from the release", nil)
		return "", "", false
	}
	policy, err := h.resolveReleaseSigningPolicy(r.Context(), releaseID, platform, arch)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, sql.ErrNoRows) {
			status = http.StatusNotFound
		}
		if errors.Is(err, db.ErrSigningPolicyConflict) {
			status = http.StatusConflict
		}
		respondError(w, status, "Release signing policy is missing or inconsistent", nil)
		return "", "", false
	}
	if policy.SigningMode == nil {
		return hash, providedSignature, true
	}
	switch *policy.SigningMode {
	case "managed":
		if !h.available(w) {
			return "", "", false
		}
		if providedSignature != "" {
			respondError(w, http.StatusBadRequest, "Managed patch signatures are generated by the server", nil)
			return "", "", false
		}
		hash = strings.ToLower(hash)
		decoded, err := hex.DecodeString(hash)
		if err != nil || len(decoded) != sha256.Size {
			respondError(w, http.StatusBadRequest, "Managed signing requires a SHA-256 artifact hash", nil)
			return "", "", false
		}
		if policy.SigningKeyID == nil {
			respondError(w, http.StatusConflict, "Managed release has no signing key", nil)
			return "", "", false
		}
		key, err := h.DB.GetSigningKeyByID(r.Context(), *policy.SigningKeyID)
		if err != nil || key.AppID != appID {
			respondError(w, http.StatusConflict, "Release signing key is unavailable", nil)
			return "", "", false
		}
		signature, err := h.signPatchHash(r.Context(), key, hash)
		if err != nil {
			respondCodedError(w, http.StatusServiceUnavailable, "managed_signing_unavailable", "Failed to unwrap or use the release signing key")
			return "", "", false
		}
		return hash, signature, true
	case "customer":
		if providedSignature == "" {
			respondError(w, http.StatusBadRequest, "Customer-signed release requires a patch signature", nil)
			return "", "", false
		}
		if _, err := base64.StdEncoding.DecodeString(providedSignature); err != nil {
			respondError(w, http.StatusBadRequest, "Invalid patch signature encoding", nil)
			return "", "", false
		}
		return hash, providedSignature, true
	case "unsigned":
		if providedSignature != "" {
			respondError(w, http.StatusBadRequest, "Unsigned release does not accept a patch signature", nil)
			return "", "", false
		}
		return hash, "", true
	default:
		respondError(w, http.StatusConflict, "Unknown release signing policy", nil)
		return "", "", false
	}
}
func sameSigningPolicy(a, b db.ArtifactRow) bool {
	if a.SigningMode == nil || b.SigningMode == nil {
		return a.SigningMode == nil && b.SigningMode == nil
	}
	if *a.SigningMode != *b.SigningMode {
		return false
	}
	if a.SigningKeyID == nil || b.SigningKeyID == nil {
		return a.SigningKeyID == nil && b.SigningKeyID == nil
	}
	return *a.SigningKeyID == *b.SigningKeyID
}

// resolveReleaseSigningPolicy maps device CPU architectures to the CLI's baseline
// containers. All selected containers and supplements must agree on the trust anchor.
func (h *SigningHandler) resolveReleaseSigningPolicy(ctx context.Context, releaseID int, platform, arch string) (*db.ArtifactRow, error) {
	artifacts, err := h.DB.GetReleaseArtifacts(ctx, releaseID, nil, &platform)
	if err != nil {
		return nil, err
	}
	primaryTags := map[string][]string{
		"ios":   {"xcarchive", "xcframework", "runner"},
		"macos": {"app"}, "linux": {"bundle"}, "windows": {"win_archive"},
		"android": {"aab", "aar"},
	}[platform]
	isPrimary := func(tag string) bool {
		if tag == arch && arch != "" {
			return true
		}
		for _, candidate := range primaryTags {
			if tag == candidate {
				return true
			}
		}
		return false
	}
	var policy *db.ArtifactRow
	for i := range artifacts {
		if isPrimary(artifacts[i].Arch) {
			policy = &artifacts[i]
			break
		}
	}
	if policy == nil {
		for _, artifact := range artifacts {
			if artifact.SigningMode != nil && *artifact.SigningMode == "managed" {
				return nil, db.ErrSigningPolicyConflict
			}
		}
		return nil, sql.ErrNoRows
	}
	for _, artifact := range artifacts {
		if isPrimary(artifact.Arch) || artifact.Arch == platform+"_supplement" {
			if !sameSigningPolicy(*policy, artifact) {
				return nil, db.ErrSigningPolicyConflict
			}
		}
	}
	return policy, nil
}
