package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/shorebird-server/internal/selection"
	"github.com/shorebird-server/internal/storage"
)

// Reconstruct the publisher's bounded empty-base literal transport, then check
// the installed encrypted envelope hash and declared policy. The stored object
// hash is deliberately not the installed artifact hash. Decryption and runtime
// validation remain the engine's job.
func validateInterpreterObject(r *http.Request, objects storage.Store, key string, d selection.Descriptor) error {
	reader, e := objects.GetObject(r.Context(), key, false)
	if e != nil {
		return e
	}
	defer reader.Close()
	compressed, e := readBoundedPatchBytes(reader, maxEncryptedPatchTransportBytes)
	if e != nil {
		return e
	}
	data, e := reconstructInterpreterTransport(compressed)
	if e != nil {
		return e
	}
	if d.Target.ArtifactHash == nil || sha256Hex(data) != *d.Target.ArtifactHash {
		return fmt.Errorf("artifact hash mismatch")
	}
	var envelope struct {
		Format   string `json:"format"`
		Metadata struct {
			AppID            string `json:"app_id"`
			FlavorID         string `json:"flavor_id"`
			LicenseType      string `json:"license_type"`
			BaseSnapshotHash string `json:"base_snapshot_hash"`
		} `json:"metadata"`
		Encryption struct {
			Algorithm string `json:"algorithm"`
			KeyID     string `json:"key_id"`
		} `json:"encryption"`
	}
	if e = json.Unmarshal(data, &envelope); e != nil {
		return e
	}
	if envelope.Format != "open-aot-vmcode-encrypted-v1" || envelope.Metadata.AppID != d.Scope.AppID || envelope.Metadata.BaseSnapshotHash != d.Scope.BaseArtifactHash || envelope.Metadata.FlavorID != d.VariantID || envelope.Metadata.LicenseType != d.LicenseType || envelope.Encryption.Algorithm != "AES-256-GCM" || d.Target.ArtifactKeyID == nil || envelope.Encryption.KeyID != *d.Target.ArtifactKeyID {
		return fmt.Errorf("artifact policy mismatch")
	}
	return nil
}
