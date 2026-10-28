package handlers

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/shorebird-server/internal/db"
	"github.com/shorebird-server/internal/models"
	"github.com/shorebird-server/internal/storage"
)

const (
	PatchDeliveryEncryptionOff             = "off"
	PatchDeliveryEncryptionPerDeviceAESGCM = "per_device_aes_gcm"
)

type PatchDeliveryConfig struct {
	EncryptionMode        string
	AESSecret             []byte
	CacheEncryptedPatches bool
}

type encryptedPatchDelivery struct {
	downloadURL string
	encryption  *models.PatchEncryptionMetadata
}

// Required encryption is a capability gate, not a client-selectable downgrade.
func (h *DeviceHandler) validatePatchDeliveryRequest(w http.ResponseWriter, req models.PatchCheckRequest) bool {
	switch h.PatchDelivery.EncryptionMode {
	case "", PatchDeliveryEncryptionOff:
		return true
	case PatchDeliveryEncryptionPerDeviceAESGCM:
		if !req.AcceptEncryptedPatch {
			respondCodedError(w, http.StatusBadRequest, "encrypted_patch_capability_required", "This server requires accept_encrypted_patch=true; clients must provision a compatible decryption key before opting in")
			return false
		}
		if req.ClientID == nil || strings.TrimSpace(*req.ClientID) == "" {
			respondCodedError(w, http.StatusBadRequest, "encrypted_patch_client_id_required", "Encrypted patch delivery requires a nonempty client_id")
			return false
		}
		if len(h.PatchDelivery.AESSecret) == 0 {
			respondCodedError(w, http.StatusServiceUnavailable, "encrypted_patch_delivery_unavailable", "PATCH_DELIVERY_AES_SECRET is required for encrypted delivery")
			return false
		}
		return true
	default:
		respondCodedError(w, http.StatusServiceUnavailable, "encrypted_patch_delivery_unavailable", "Unknown patch delivery encryption mode")
		return false
	}
}

func (h *DeviceHandler) maybeEncryptedPatchDelivery(ctx context.Context, appID uuid.UUID, releaseID int, req models.PatchCheckRequest, patch *db.PatchWithArtifactRow) (*encryptedPatchDelivery, error) {
	if h.PatchDelivery.EncryptionMode != "" && h.PatchDelivery.EncryptionMode != PatchDeliveryEncryptionOff && !h.shouldEncryptPatchDelivery(req) {
		return nil, fmt.Errorf("required patch encryption capability is missing")
	}
	if !h.shouldEncryptPatchDelivery(req) {
		downloadURL, err := h.Storage.GeneratePublicDownloadURL(ctx, patch.StorageKey)
		if err != nil {
			return nil, err
		}
		return &encryptedPatchDelivery{downloadURL: downloadURL}, nil
	}
	if len(h.PatchDelivery.AESSecret) == 0 {
		return nil, fmt.Errorf("patch delivery encryption is enabled but PATCH_DELIVERY_AES_SECRET is empty")
	}

	clientID := *req.ClientID
	deviceIDHash := sha256Hex([]byte(clientID))
	aad := patchDeliveryAAD(appID, releaseID, req, patch, deviceIDHash)
	key := derivePatchDeliveryKey(h.PatchDelivery.AESSecret, aad)
	nonce := derivePatchDeliveryNonce(h.PatchDelivery.AESSecret, aad)
	keyID := base64.RawURLEncoding.EncodeToString(hmacDigest(h.PatchDelivery.AESSecret, []byte("key-id\x00"+aad))[:12])

	plaintext, err := h.readPatchObject(ctx, patch.StorageKey)
	if err != nil {
		return nil, fmt.Errorf("read plaintext patch: %w", err)
	}
	ciphertext, err := encryptPatchPayload(key, nonce, []byte(aad), plaintext)
	if err != nil {
		return nil, err
	}

	cacheKey := storage.GenerateDeviceEncryptedPatchStorageKey(
		appID.String(),
		releaseID,
		patch.Number,
		req.Platform,
		req.Arch,
		patch.Hash,
		deviceIDHash,
		keyID,
	)
	cachedCiphertext := ciphertext
	if h.PatchDelivery.CacheEncryptedPatches {
		if existing, err := h.readPatchObject(ctx, cacheKey); err == nil && len(existing) > 0 {
			cachedCiphertext = existing
		} else if err := h.Storage.UploadObject(ctx, cacheKey, bytes.NewReader(ciphertext), int64(len(ciphertext)), "application/octet-stream", true); err != nil {
			return nil, fmt.Errorf("cache encrypted patch: %w", err)
		}
	} else if err := h.Storage.UploadObject(ctx, cacheKey, bytes.NewReader(ciphertext), int64(len(ciphertext)), "application/octet-stream", true); err != nil {
		return nil, fmt.Errorf("write encrypted patch: %w", err)
	}

	downloadURL, err := h.Storage.GeneratePublicDownloadURL(ctx, cacheKey)
	if err != nil {
		return nil, err
	}

	return &encryptedPatchDelivery{
		downloadURL: downloadURL,
		encryption: &models.PatchEncryptionMetadata{
			Algorithm:     "AES-256-GCM",
			KDF:           "HMAC-SHA256",
			KeyID:         keyID,
			Nonce:         base64.RawURLEncoding.EncodeToString(nonce),
			AAD:           base64.RawURLEncoding.EncodeToString([]byte(aad)),
			AADHash:       sha256Hex([]byte(aad)),
			EncryptedHash: sha256Hex(cachedCiphertext),
			DeviceIDHash:  deviceIDHash,
			CacheKey:      cacheKey,
		},
	}, nil
}

func (h *DeviceHandler) shouldEncryptPatchDelivery(req models.PatchCheckRequest) bool {
	if h.PatchDelivery.EncryptionMode != PatchDeliveryEncryptionPerDeviceAESGCM {
		return false
	}
	if !req.AcceptEncryptedPatch {
		return false
	}
	return req.ClientID != nil && *req.ClientID != ""
}

func (h *DeviceHandler) readPatchObject(ctx context.Context, objectKey string) ([]byte, error) {
	reader, err := h.Storage.GetObject(ctx, objectKey, true)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

func patchDeliveryAAD(appID uuid.UUID, releaseID int, req models.PatchCheckRequest, patch *db.PatchWithArtifactRow, deviceIDHash string) string {
	return fmt.Sprintf(
		"open-aot-patch-delivery-v1\napp_id=%s\nrelease_id=%d\npatch_number=%d\npatch_hash=%s\nplatform=%s\narch=%s\ndevice_id_hash=%s",
		appID.String(),
		releaseID,
		patch.Number,
		patch.Hash,
		req.Platform,
		req.Arch,
		deviceIDHash,
	)
}

func derivePatchDeliveryKey(secret []byte, aad string) []byte {
	return hmacDigest(secret, []byte("key\x00"+aad))
}

func derivePatchDeliveryNonce(secret []byte, aad string) []byte {
	sum := hmacDigest(secret, []byte("nonce\x00"+aad))
	return sum[:12]
}

func encryptPatchPayload(key, nonce, aad, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

func hmacDigest(secret, message []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(message)
	return mac.Sum(nil)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
