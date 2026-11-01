package handlers

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/shorebird-server/internal/db"
	"github.com/shorebird-server/internal/models"
	"github.com/shorebird-server/internal/selection"
)

type selectionRequestContext struct {
	AppID                   string  `json:"app_id"`
	ReleaseVersion          string  `json:"release_version"`
	Platform                string  `json:"platform"`
	Arch                    string  `json:"arch"`
	Channel                 string  `json:"channel"`
	ClientIDHash            string  `json:"client_id_hash"`
	Nonce                   string  `json:"nonce"`
	BaseArtifactHash        string  `json:"base_artifact_hash"`
	HostABIHash             *string `json:"host_abi_hash"`
	RuntimeProfile          string  `json:"runtime_profile"`
	AcceptedSelectionEpoch  string  `json:"accepted_selection_epoch"`
	AcceptedSelectionDigest *string `json:"accepted_selection_digest"`
}
type selectionDelivery struct {
	Number        string                          `json:"number"`
	Hash          string                          `json:"hash"`
	DownloadURL   string                          `json:"download_url"`
	HashSignature string                          `json:"hash_signature"`
	Encryption    *models.PatchEncryptionMetadata `json:"encryption"`
}
type selectionPayload struct {
	Version         int                     `json:"version"`
	Request         selectionRequestContext `json:"request"`
	Selection       selection.Descriptor    `json:"selection"`
	SelectionDigest string                  `json:"selection_digest"`
	Delivery        *selectionDelivery      `json:"delivery"`
}
type selectionResponse struct {
	Version         int                                `json:"version"`
	Selection       selection.Descriptor               `json:"selection"`
	SelectionDigest string                             `json:"selection_digest"`
	Delivery        *selectionDelivery                 `json:"delivery"`
	Authentication  models.PatchResponseAuthentication `json:"authentication"`
}

func decodePatchCheck(r *http.Request, req *models.PatchCheckRequest) error {
	defer r.Body.Close()
	data, e := io.ReadAll(io.LimitReader(r.Body, selection.MaxJSON+1))
	if e != nil {
		return e
	}
	if len(data) > selection.MaxJSON {
		return fmt.Errorf("request too large")
	}
	if e = json.Unmarshal(data, req); e != nil {
		return e
	}
	if req.SelectionProtocol == 2 {
		if e = selection.StrictJSON(data, req); e != nil {
			return e
		}
		var keys map[string]json.RawMessage
		_ = json.Unmarshal(data, &keys)
		for _, key := range []string{"selection_protocol", "app_id", "release_version", "platform", "arch", "client_id", "nonce", "base_artifact_hash", "host_abi_hash", "runtime_profile", "accepted_selection_epoch", "accepted_selection_digest"} {
			if _, ok := keys[key]; !ok {
				return fmt.Errorf("missing %s", key)
			}
		}
	}
	return nil
}
func equalNullable(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
func verifyArtifactSignature(key *db.SigningKeyRow, hash, signature string) bool {
	block, _ := pem.Decode([]byte(key.PublicKeyPEM))
	if block == nil {
		return false
	}
	parsed, e := x509.ParsePKIXPublicKey(block.Bytes)
	if e != nil {
		return false
	}
	public, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return false
	}
	sig, e := base64.StdEncoding.DecodeString(signature)
	if e != nil {
		return false
	}
	digest := sha256.Sum256([]byte(hash))
	return rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], sig) == nil
}
func (h *DeviceHandler) selectionCheck(w http.ResponseWriter, r *http.Request, req models.PatchCheckRequest, releaseID int) {
	if !h.Signing.available(w) {
		return
	}
	if req.Channel == "" {
		req.Channel = "stable"
	}
	if req.ClientID == nil || *req.ClientID == "" || !selection.UUID4(req.Nonce) || !selection.Identifier(req.Channel) {
		selectionFailure(w, invalid("invalid_selection_request"))
		return
	}
	accepted, e := selection.Decimal(req.AcceptedSelectionEpoch, 0, 9223372036854775807)
	if e != nil || (accepted == 0 && req.AcceptedSelectionDigest != nil) || (accepted > 0 && (req.AcceptedSelectionDigest == nil || !selection.Hash(*req.AcceptedSelectionDigest))) {
		selectionFailure(w, invalid("invalid_selection_epoch"))
		return
	}
	clientHash := selection.ClientHash(*req.ClientID)
	var result selection.Result
	var patch *db.PatchWithArtifactRow
	var keyID int
	now := time.Now().UTC().Unix()
	e = h.DB.SelectionTransaction(r.Context(), releaseID, func(s *selection.State, c *db.SelectionCatalog) error {
		scope, e := usableScope(s, c, req.Platform, req.Arch)
		if e != nil {
			return e
		}
		if req.AppID != scope.AppID || req.ReleaseVersion != scope.ReleaseVersion || req.BaseArtifactHash != scope.BaseArtifactHash || req.RuntimeProfile != scope.RuntimeProfile || !equalNullable(req.HostABIHash, scope.HostABIHash) {
			return conflict("selection_scope_mismatch")
		}
		scope.ClientIDHash = clientHash
		installed := selection.InstallKey(req.Platform, req.Arch, clientHash)
		var exists bool
		result, exists = s.Selections[installed]
		if !exists {
			if accepted > 0 {
				return conflict("selection_state_behind")
			}
			d := selection.Base(scope, req.Channel, "1", "initial-free", strconv.FormatInt(now, 10))
			digest, e := d.Digest()
			if e != nil {
				return e
			}
			result = selection.Result{Selection: d, SelectionDigest: digest}
			s.Selections[installed] = result
		}
		d := result.Selection
		epoch, _ := selection.Decimal(d.Epoch, 1, 9223372036854775807)
		if accepted > epoch {
			return conflict("selection_state_behind")
		}
		if d.Channel != req.Channel {
			return conflict("selection_channel_mismatch")
		}
		revoked := false
		if d.Target.Kind == "patch" {
			n, _ := selection.Decimal(*d.Target.PatchNumber, 1, 2147483647)
			revoked = c.Revoked[int(n)]
			if p, ok := c.Patch(req.Platform, req.Arch, *d.Target.PatchNumber); ok && p.OfflineExpiresAt.Valid && now >= p.OfflineExpiresAt.Time.Unix() {
				revoked = true
			}
		}
		expired := false
		if d.OfflineValidUntil != nil {
			until, _ := selection.Decimal(*d.OfflineValidUntil, 0, 253402300799)
			expired = now >= until
		}
		if revoked || expired {
			if epoch == 9223372036854775807 {
				return conflict("selection_epoch_exhausted")
			}
			next := strconv.FormatInt(epoch+1, 10)
			d = selection.Base(scope, req.Channel, next, "server-free-"+next, strconv.FormatInt(now, 10))
			digest, e := d.Digest()
			if e != nil {
				return e
			}
			result = selection.Result{Selection: d, SelectionDigest: digest}
			s.Selections[installed] = result
		}
		if accepted == epoch && req.AcceptedSelectionDigest != nil && *req.AcceptedSelectionDigest != result.SelectionDigest && !(revoked || expired) {
			return conflict("selection_epoch_conflict")
		}
		record := s.Scopes[selection.ScopeKey(req.Platform, req.Arch)]
		policy := c.Artifacts[record.Record.ReleaseArtifactID]
		if policy.SigningKeyID == nil {
			return conflict("selection_signing_unavailable")
		}
		keyID = *policy.SigningKeyID
		if result.Selection.Target.Kind == "patch" {
			p, ok := c.Patch(req.Platform, req.Arch, *result.Selection.Target.PatchNumber)
			if !ok || p.Hash != *result.Selection.Target.ArtifactHash || p.HashSignature == nil || *p.HashSignature == "" {
				return conflict("selection_content_unavailable")
			}
			patch = &p
		}
		return nil
	})
	if e != nil {
		selectionFailure(w, e)
		return
	}
	key, e := h.DB.GetSigningKeyByID(r.Context(), keyID)
	if e != nil || key.AppID.String() != req.AppID {
		selectionFailure(w, conflict("selection_signing_unavailable"))
		return
	}
	var delivery *selectionDelivery
	if patch != nil {
		if !verifyArtifactSignature(key, patch.Hash, *patch.HashSignature) {
			selectionFailure(w, conflict("selection_content_unavailable"))
			return
		}
		var url string
		var encryption *models.PatchEncryptionMetadata
		if result.Selection.Scope.RuntimeProfile == "native-aot" {
			if h.PatchDelivery.EncryptionMode != PatchDeliveryEncryptionPerDeviceAESGCM || !req.AcceptEncryptedPatch {
				selectionFailure(w, conflict("selection_encryption_unavailable"))
				return
			}
			encrypted, e := h.maybeEncryptedPatchDelivery(r.Context(), key.AppID, releaseID, req, patch)
			if e != nil || encrypted.encryption == nil {
				selectionFailure(w, conflict("selection_encryption_unavailable"))
				return
			}
			url, encryption = encrypted.downloadURL, encrypted.encryption
		} else {
			if e := validateInterpreterObject(r, h.Storage, patch.StorageKey, result.Selection); e != nil {
				selectionFailure(w, conflict("selection_content_unavailable"))
				return
			}
			url, e = h.Storage.GeneratePresignedDownloadURL(r.Context(), patch.StorageKey, false, 30*time.Minute)
			if e != nil {
				selectionFailure(w, conflict("selection_delivery_unavailable"))
				return
			}
		}
		if len(url) > 8192 {
			selectionFailure(w, conflict("selection_delivery_unavailable"))
			return
		}
		delivery = &selectionDelivery{Number: *result.Selection.Target.PatchNumber, Hash: patch.Hash, DownloadURL: url, HashSignature: *patch.HashSignature, Encryption: encryption}
	}
	context := selectionRequestContext{req.AppID, req.ReleaseVersion, req.Platform, req.Arch, req.Channel, clientHash, req.Nonce, req.BaseArtifactHash, req.HostABIHash, req.RuntimeProfile, req.AcceptedSelectionEpoch, req.AcceptedSelectionDigest}
	payload := selectionPayload{2, context, result.Selection, result.SelectionDigest, delivery}
	serialized, e := json.Marshal(payload)
	if e != nil || len(serialized) > selection.MaxJSON {
		selectionFailure(w, conflict("selection_response_too_large"))
		return
	}
	signature, e := h.Signing.signMessage(key, serialized)
	if e != nil {
		respondCodedError(w, 503, "managed_signing_unavailable", "Failed to sign selection response")
		return
	}
	response := selectionResponse{2, result.Selection, result.SelectionDigest, delivery, models.PatchResponseAuthentication{Payload: base64.StdEncoding.EncodeToString(serialized), Signature: signature}}
	outer, e := json.Marshal(response)
	if e != nil || len(outer) > selection.MaxJSON {
		selectionFailure(w, conflict("selection_response_too_large"))
		return
	}
	respondJSON(w, 200, response)
}
