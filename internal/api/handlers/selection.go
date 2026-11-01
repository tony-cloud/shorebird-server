package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/shorebird-server/internal/db"
	"github.com/shorebird-server/internal/selection"
)

type selectionError struct {
	Status int
	Code   string
}

func (e selectionError) Error() string { return e.Code }
func conflict(code string) error       { return selectionError{409, code} }
func invalid(code string) error        { return selectionError{400, code} }
func selectionFailure(w http.ResponseWriter, e error) {
	var se selectionError
	if errors.As(e, &se) {
		respondCodedError(w, se.Status, se.Code, se.Code)
		return
	}
	if errors.Is(e, db.ErrSelectionProtocol) {
		respondCodedError(w, 409, "selection_protocol_mismatch", e.Error())
		return
	}
	respondCodedError(w, 500, "selection_unavailable", "Selection operation failed")
}
func strictSelectionBody(r *http.Request, dst any, keys ...string) error {
	defer r.Body.Close()
	data, e := io.ReadAll(io.LimitReader(r.Body, selection.MaxJSON+1))
	if e != nil {
		return e
	}
	if e = selection.StrictJSON(data, dst); e != nil {
		return e
	}
	if keys != nil {
		return selection.ExactKeys(data, keys...)
	}
	return nil
}
func (h *ReleaseHandler) selectionAccess(w http.ResponseWriter, r *http.Request, write bool) (int, bool) {
	app, e := parseUUID(chi.URLParam(r, "appId"))
	if e != nil {
		respondError(w, 400, "Invalid app ID", nil)
		return 0, false
	}
	if _, ok := requireAppAccess(w, r, h.DB, app, write); !ok {
		return 0, false
	}
	id, e := parseIntParam(r, "releaseId")
	if e != nil {
		respondError(w, 400, "Invalid release ID", nil)
		return 0, false
	}
	if !h.releaseBelongsToApp(w, r, id, app) {
		return 0, false
	}
	return id, true
}

type registerScopeRequest struct {
	BaseArtifactHash     string  `json:"base_artifact_hash"`
	HostABIHash          *string `json:"host_abi_hash"`
	RuntimeProfile       string  `json:"runtime_profile"`
	ReleaseArtifactID    int     `json:"release_artifact_id"`
	SupplementArtifactID *int    `json:"supplement_artifact_id"`
}

func registeredArtifactsValid(stored selection.StoredScope, c *db.SelectionCatalog) bool {
	r := stored.Record
	a, ok := c.Artifacts[r.ReleaseArtifactID]
	if !ok || a.Platform != r.Scope.Platform || a.Hash != stored.ReleaseHash || a.SigningMode == nil || *a.SigningMode != "managed" || a.SigningKeyID == nil {
		return false
	}
	if r.Scope.RuntimeProfile != "native-aot" && r.SupplementArtifactID == nil {
		return false
	}
	if r.SupplementArtifactID != nil {
		b, ok := c.Artifacts[*r.SupplementArtifactID]
		if !ok || b.Platform != r.Scope.Platform || stored.SupplementHash == nil || b.Hash != *stored.SupplementHash || !sameSigningPolicy(a, b) {
			return false
		}
	}
	// Every uploaded file on this platform must retain its original trust anchor.
	for _, b := range c.Artifacts {
		if b.Platform == a.Platform && !sameSigningPolicy(a, b) {
			return false
		}
	}
	return true
}
func (h *ReleaseHandler) PutSelectionScope(w http.ResponseWriter, r *http.Request) {
	id, ok := h.selectionAccess(w, r, true)
	if !ok {
		return
	}
	var req registerScopeRequest
	if e := strictSelectionBody(r, &req, "base_artifact_hash", "host_abi_hash", "runtime_profile", "release_artifact_id", "supplement_artifact_id"); e != nil {
		selectionFailure(w, invalid("invalid_selection_scope"))
		return
	}
	platform, arch := chi.URLParam(r, "platform"), chi.URLParam(r, "arch")
	status := 201
	var result selection.ScopeRecord
	e := h.DB.SelectionTransaction(r.Context(), id, func(s *selection.State, c *db.SelectionCatalog) error {
		if c.Release.SelectionProtocol != 2 {
			return db.ErrSelectionProtocol
		}
		scope := selection.Scope{AppID: c.Release.AppID.String(), ReleaseVersion: c.Release.Version, Platform: platform, Arch: arch, BaseArtifactHash: req.BaseArtifactHash, HostABIHash: req.HostABIHash, RuntimeProfile: req.RuntimeProfile}
		if e := scope.Validate(false); e != nil || req.ReleaseArtifactID <= 0 || (req.SupplementArtifactID != nil && *req.SupplementArtifactID <= 0) {
			return invalid("invalid_selection_scope")
		}
		record := selection.ScopeRecord{Scope: scope, ReleaseArtifactID: req.ReleaseArtifactID, SupplementArtifactID: req.SupplementArtifactID}
		key := selection.ScopeKey(platform, arch)
		if old, exists := s.Scopes[key]; exists {
			comparison := old.Record
			comparison.Published = false
			if !reflect.DeepEqual(comparison, record) {
				return conflict("selection_scope_immutable")
			}
			result = old.Record
			status = 200
			return nil
		}
		if s.Published[platform] || (c.Statuses[platform] != "" && c.Statuses[platform] != "draft") {
			return conflict("selection_scope_immutable")
		}
		a, exists := c.Artifacts[req.ReleaseArtifactID]
		if !exists {
			return conflict("selection_scope_incomplete")
		}
		stored := selection.StoredScope{Record: record, ReleaseHash: a.Hash}
		if req.SupplementArtifactID != nil {
			b, exists := c.Artifacts[*req.SupplementArtifactID]
			if !exists {
				return conflict("selection_scope_incomplete")
			}
			stored.SupplementHash = &b.Hash
		}
		if !registeredArtifactsValid(stored, c) {
			return conflict("selection_scope_incomplete")
		}
		s.Scopes[key] = stored
		c.Statuses[platform] = "draft"
		result = record
		return nil
	})
	if e != nil {
		selectionFailure(w, e)
		return
	}
	respondJSON(w, status, result)
}
func (h *ReleaseHandler) GetSelectionScopes(w http.ResponseWriter, r *http.Request) {
	id, ok := h.selectionAccess(w, r, false)
	if !ok {
		return
	}
	result := []selection.ScopeRecord{}
	e := h.DB.SelectionTransaction(r.Context(), id, func(s *selection.State, c *db.SelectionCatalog) error {
		for _, scope := range s.Scopes {
			result = append(result, scope.Record)
		}
		return nil
	})
	if e != nil {
		selectionFailure(w, e)
		return
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i].Scope, result[j].Scope
		if a.Platform != b.Platform {
			return a.Platform < b.Platform
		}
		return a.Arch < b.Arch
	})
	respondJSON(w, 200, map[string]any{"scopes": result})
}

func publishSelection(s *selection.State, c *db.SelectionCatalog, platform, status string, arches []string) error {
	if !selection.Platform(platform) || (status != "active" && status != "draft" && status != "inactive") {
		return invalid("invalid_release_status")
	}
	if s.Published[platform] && status == "draft" {
		return conflict("selection_scope_immutable")
	}
	if status == "active" {
		if len(arches) == 0 {
			return invalid("selection_arches_required")
		}
		expected := []string{}
		for _, scope := range s.Scopes {
			if scope.Record.Scope.Platform == platform {
				if !registeredArtifactsValid(scope, c) {
					return conflict("selection_scope_incomplete")
				}
				expected = append(expected, scope.Record.Scope.Arch)
			}
		}
		given := append([]string(nil), arches...)
		sort.Strings(given)
		sort.Strings(expected)
		for i, a := range given {
			if !selection.Arch(a) || (i > 0 && a == given[i-1]) {
				return invalid("invalid_selection_arches")
			}
		}
		if len(expected) == 0 || !reflect.DeepEqual(given, expected) {
			return conflict("selection_scope_incomplete")
		}
		s.Published[platform] = true
		for key, scope := range s.Scopes {
			if scope.Record.Scope.Platform == platform {
				scope.Record.Published = true
				s.Scopes[key] = scope
			}
		}
	}
	c.Statuses[platform] = status
	return nil
}
func usableScope(s *selection.State, c *db.SelectionCatalog, platform, arch string) (selection.Scope, error) {
	if c.Release.SelectionProtocol != 2 {
		return selection.Scope{}, db.ErrSelectionProtocol
	}
	v, ok := s.Scopes[selection.ScopeKey(platform, arch)]
	if !ok || !v.Record.Published || !s.Published[platform] || c.Statuses[platform] != "active" || !registeredArtifactsValid(v, c) {
		return selection.Scope{}, conflict("selection_scope_incomplete")
	}
	return v.Record.Scope, nil
}
func validateMappingTarget(c *db.SelectionCatalog, scope selection.Scope, variant string, m selection.Mapping) error {
	scope.ClientIDHash = selection.ClientHash("validation")
	d := selection.Descriptor{Epoch: "1", Scope: scope, Channel: m.Channel, VariantID: variant, LicenseType: m.LicenseType, EntitlementRevision: "validation", Target: m.Target, NotBefore: "0", Fallback: selection.Fallback{Kind: "base", VariantID: "free", LicenseType: "free"}}
	if e := d.Validate(); e != nil {
		return invalid("invalid_variant_target")
	}
	if m.Target.Kind == "base" {
		return nil
	}
	p, ok := c.Patch(m.Platform, m.Arch, *m.Target.PatchNumber)
	if !ok || p.Hash != *m.Target.ArtifactHash || p.HashSignature == nil || *p.HashSignature == "" || c.Revoked[p.Number] || (p.OfflineExpiresAt.Valid && time.Now().UTC().Unix() >= p.OfflineExpiresAt.Time.Unix()) {
		return conflict("variant_content_unavailable")
	}
	return nil
}
func (h *ReleaseHandler) PutVariant(w http.ResponseWriter, r *http.Request) {
	id, ok := h.selectionAccess(w, r, true)
	if !ok {
		return
	}
	var req selection.Mapping
	if e := strictSelectionBody(r, &req, "platform", "arch", "channel", "license_type", "target"); e != nil {
		selectionFailure(w, invalid("invalid_variant"))
		return
	}
	variant := chi.URLParam(r, "variantId")
	if !selection.Identifier(variant) {
		selectionFailure(w, invalid("invalid_variant"))
		return
	}
	var signingKey *db.SigningKeyRow
	if req.Target.Kind == "patch" {
		policy, e := h.Signing.resolveReleaseSigningPolicy(r.Context(), id, req.Platform, req.Arch)
		if e != nil || policy.SigningKeyID == nil {
			selectionFailure(w, conflict("variant_content_unavailable"))
			return
		}
		signingKey, e = h.DB.GetSigningKeyByID(r.Context(), *policy.SigningKeyID)
		if e != nil {
			selectionFailure(w, conflict("variant_content_unavailable"))
			return
		}
	}
	e := h.DB.SelectionTransaction(r.Context(), id, func(s *selection.State, c *db.SelectionCatalog) error {
		scope, e := usableScope(s, c, req.Platform, req.Arch)
		if e != nil {
			return e
		}
		if e := validateMappingTarget(c, scope, variant, req); e != nil {
			return e
		}
		if req.Target.Kind == "patch" {
			p, _ := c.Patch(req.Platform, req.Arch, *req.Target.PatchNumber)
			if signingKey.AppID != c.Release.AppID || !verifyArtifactSignature(signingKey, p.Hash, *p.HashSignature) {
				return conflict("variant_content_unavailable")
			}
			if scope.RuntimeProfile != "native-aot" {
				scope.ClientIDHash = selection.ClientHash("validation")
				d := selection.Descriptor{Scope: scope, VariantID: variant, LicenseType: req.LicenseType, Target: req.Target}
				if e := validateInterpreterObject(r, h.Storage, p.StorageKey, d); e != nil {
					return conflict("variant_content_unavailable")
				}
			}
		}
		s.Mappings[selection.MappingKey(req.Platform, req.Arch, req.Channel, variant)] = req
		return nil
	})
	if e != nil {
		selectionFailure(w, e)
		return
	}
	respondJSON(w, 200, req)
}

type assignSelectionRequest struct {
	ClientID            string  `json:"client_id"`
	Platform            string  `json:"platform"`
	Arch                string  `json:"arch"`
	Channel             string  `json:"channel"`
	VariantID           string  `json:"variant_id"`
	EntitlementRevision string  `json:"entitlement_revision"`
	NotBefore           string  `json:"not_before"`
	OfflineValidUntil   *string `json:"offline_valid_until"`
	ExpectedEpoch       string  `json:"expected_epoch"`
	IdempotencyKey      string  `json:"idempotency_key"`
}

func (h *ReleaseHandler) AssignSelection(w http.ResponseWriter, r *http.Request) {
	id, ok := h.selectionAccess(w, r, true)
	if !ok {
		return
	}
	var req assignSelectionRequest
	if e := strictSelectionBody(r, &req, "client_id", "platform", "arch", "channel", "variant_id", "entitlement_revision", "not_before", "offline_valid_until", "expected_epoch", "idempotency_key"); e != nil {
		selectionFailure(w, invalid("invalid_selection"))
		return
	}
	if req.ClientID == "" || !selection.UUID4(req.IdempotencyKey) || !selection.Identifier(req.Channel) || !selection.Identifier(req.VariantID) {
		selectionFailure(w, invalid("invalid_selection"))
		return
	}
	expected, e := selection.Decimal(req.ExpectedEpoch, 0, 9223372036854775807)
	if e != nil {
		selectionFailure(w, invalid("invalid_selection_epoch"))
		return
	}
	encoded, _ := json.Marshal(req)
	var result selection.Result
	e = h.DB.SelectionTransaction(r.Context(), id, func(s *selection.State, c *db.SelectionCatalog) error {
		if c.Release.SelectionProtocol != 2 {
			return db.ErrSelectionProtocol
		}
		if old, ok := s.Idempotency[req.IdempotencyKey]; ok {
			if old.Body != string(encoded) {
				return conflict("selection_idempotency_conflict")
			}
			result = old.Result
			return nil
		}
		scope, e := usableScope(s, c, req.Platform, req.Arch)
		if e != nil {
			return e
		}
		scope.ClientIDHash = selection.ClientHash(req.ClientID)
		key := selection.InstallKey(req.Platform, req.Arch, scope.ClientIDHash)
		old := s.Selections[key]
		epoch := int64(0)
		if old.Selection.Epoch != "" {
			epoch, _ = selection.Decimal(old.Selection.Epoch, 1, 9223372036854775807)
		}
		if epoch != expected {
			return conflict("selection_epoch_conflict")
		}
		if epoch == 9223372036854775807 {
			return conflict("selection_epoch_exhausted")
		}
		m, ok := s.Mappings[selection.MappingKey(req.Platform, req.Arch, req.Channel, req.VariantID)]
		if !ok {
			return conflict("variant_not_found")
		}
		if e := validateMappingTarget(c, scope, req.VariantID, m); e != nil {
			return e
		}
		d := selection.Descriptor{Epoch: strconv.FormatInt(epoch+1, 10), Scope: scope, Channel: req.Channel, VariantID: req.VariantID, LicenseType: m.LicenseType, EntitlementRevision: req.EntitlementRevision, Target: m.Target, NotBefore: req.NotBefore, OfflineValidUntil: req.OfflineValidUntil, Fallback: selection.Fallback{Kind: "base", VariantID: "free", LicenseType: "free"}}
		if d.Target.Kind == "patch" {
			p, _ := c.Patch(req.Platform, req.Arch, *d.Target.PatchNumber)
			if p.OfflineExpiresAt.Valid {
				if d.OfflineValidUntil == nil {
					return conflict("selection_exceeds_content_expiry")
				}
				until, e := selection.Decimal(*d.OfflineValidUntil, 0, 253402300799)
				if e != nil || until > p.OfflineExpiresAt.Time.Unix() {
					return conflict("selection_exceeds_content_expiry")
				}
			}
		}
		digest, e := d.Digest()
		if e != nil {
			return invalid("invalid_selection")
		}
		if d.Target.Kind == "base" && d.OfflineValidUntil != nil {
			return invalid("free_base_has_no_expiry")
		}
		result = selection.Result{Selection: d, SelectionDigest: digest}
		s.Selections[key] = result
		s.Idempotency[req.IdempotencyKey] = selection.Idempotent{Body: string(encoded), Result: result}
		return nil
	})
	if e != nil {
		selectionFailure(w, e)
		return
	}
	respondJSON(w, 200, result)
}
func immutableReleaseKeys(data []byte) bool {
	var obj map[string]json.RawMessage
	if json.Unmarshal(data, &obj) != nil {
		return false
	}
	for key, value := range obj {
		switch key {
		case "version", "selection_published", "client_id_hash", "selection_protocol", "scope", "selection_scope", "selection_scopes", "base_artifact_hash", "host_abi_hash", "runtime_profile", "app_id", "release_version", "arch", "release_artifact_id", "supplement_artifact_id":
			return true
		case "metadata":
			var metadata map[string]json.RawMessage
			_ = json.Unmarshal(value, &metadata)
			if _, ok := metadata["platform"]; ok {
				return true
			}
			if _, ok := metadata["selection_arches"]; ok {
				return true
			}
			if immutableReleaseKeys(value) {
				return true
			}
		}
	}
	return false
}
func readReleaseUpdate(r *http.Request, dst any) (bool, error) {
	defer r.Body.Close()
	b, e := io.ReadAll(io.LimitReader(r.Body, selection.MaxJSON+1))
	if e != nil {
		return false, e
	}
	if immutableReleaseKeys(b) {
		return true, nil
	}
	return false, selection.StrictJSON(b, dst)
}

func decodeReleaseCreate(r *http.Request, dst any) error {
	defer r.Body.Close()
	data, e := io.ReadAll(io.LimitReader(r.Body, selection.MaxJSON+1))
	if e != nil {
		return e
	}
	if e = selection.StrictJSON(data, dst); e != nil {
		return e
	}
	var values map[string]json.RawMessage
	_ = json.Unmarshal(data, &values)
	if value, ok := values["selection_protocol"]; ok && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return invalid("invalid_selection_protocol")
	}
	return nil
}
