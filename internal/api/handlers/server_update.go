package handlers

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/shorebird-server/internal/api/middleware"
	authpkg "github.com/shorebird-server/internal/auth"
	"github.com/shorebird-server/internal/db"
	"github.com/shorebird-server/internal/updater"
)

// ServerUpdateHandler exposes the server's self-update to global
// administrators (users.is_admin). Organization admins have no access: the
// executable is a server-wide resource.
type ServerUpdateHandler struct {
	DB      db.Store
	Service *updater.Service
	Auditor updater.Auditor
	// LocalSecret enables the local upload route (LocalRoutes) for the host's
	// root administrator; empty: not mounted. See docs/SELF_UPDATE.md.
	LocalSecret string
	reauth      reauthLimiter
}

const maxServerUpdateJSON = 16 << 10

// Routes registers the handler under an authenticated router.
func (h *ServerUpdateHandler) Routes(r chi.Router) {
	r.Get("/admin/server/update", h.admin(h.getStatus))
	r.Put("/admin/server/update", h.admin(h.putSettings))
	r.Post("/admin/server/update/check", h.admin(h.check))
	r.Post("/admin/server/update/install", h.admin(h.install))
	r.Post("/admin/server/update/upload", h.admin(h.upload))
	r.Post("/admin/server/update/rollback", h.admin(h.rollback))
	r.Get("/admin/server/update/audit", h.admin(h.audit))
}

type adminHandlerFunc func(http.ResponseWriter, *http.Request, *db.UserRow)

func (h *ServerUpdateHandler) admin(next adminHandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		claims := middleware.GetClaims(r)
		if claims == nil {
			respondCodedError(w, http.StatusUnauthorized, "authentication_required", "Unauthorized")
			return
		}
		user, err := h.DB.GetUserByID(r.Context(), claims.UserID)
		if err != nil || user == nil || !user.IsAdmin {
			respondCodedError(w, http.StatusForbidden, "admin_required", "Admin access required")
			return
		}
		next(w, r, user)
	}
}

func (h *ServerUpdateHandler) record(r *http.Request, user *db.UserRow, action, result, auth string, details map[string]any) {
	if h.Auditor == nil {
		return
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	event := updater.AuditEvent{Action: action, Result: result, Auth: auth, RemoteAddr: host, Details: details}
	if user != nil {
		event.ActorID, event.ActorEmail = user.ID, user.Email
	}
	h.Auditor.Record(event)
}

// updateErrorStatus maps updater error codes to HTTP statuses.
func updateErrorStatus(code string) int {
	switch code {
	case "invalid_config", "invalid_interval", "invalid_channel", "invalid_request":
		return http.StatusBadRequest
	case "config_write_failed", "rollback_failed":
		return http.StatusInternalServerError
	case "invalid_zip", "signature_invalid", "untrusted_signer", "wrong_platform", "version_mismatch", "checksum_mismatch",
		"invalid_release", "unsupported_platform", "trust_unconfigured":
		return http.StatusUnprocessableEntity
	}
	return http.StatusConflict
}

func respondUpdateError(w http.ResponseWriter, err error) {
	code := err.Error()
	respondCodedError(w, updateErrorStatus(code), code, "Server update refused: "+code)
}

func decodeStrict(r *http.Request, w http.ResponseWriter, v any) bool {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxServerUpdateJSON))
	if err != nil {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if dec.Decode(v) != nil {
		return false
	}
	var extra any
	return dec.Decode(&extra) == io.EOF
}

func (h *ServerUpdateHandler) getStatus(w http.ResponseWriter, r *http.Request, _ *db.UserRow) {
	respondJSON(w, http.StatusOK, h.Service.Status())
}

func (h *ServerUpdateHandler) putSettings(w http.ResponseWriter, r *http.Request, user *db.UserRow) {
	var req struct {
		Channel              *string `json:"channel"`
		UseMirror            *bool   `json:"use_mirror"`
		AutoUpdate           *bool   `json:"auto_update"`
		CheckIntervalSeconds *int    `json:"check_interval_seconds"`
	}
	if !decodeStrict(r, w, &req) || req.AutoUpdate == nil || req.CheckIntervalSeconds == nil {
		respondUpdateError(w, errCode("invalid_config"))
		return
	}
	settings := h.Service.Status().Settings
	settings.AutoUpdate = *req.AutoUpdate
	settings.CheckIntervalSeconds = *req.CheckIntervalSeconds
	if req.Channel != nil {
		settings.Channel = *req.Channel
	}
	if req.UseMirror != nil {
		settings.UseMirror = *req.UseMirror
	}
	details := map[string]any{"channel": settings.Channel, "use_mirror": settings.UseMirror, "auto_update": settings.AutoUpdate,
		"check_interval_seconds": settings.CheckIntervalSeconds}
	if err := h.Service.Configure(settings); err != nil {
		h.record(r, user, "server.update.configure", err.Error(), "token", details)
		respondUpdateError(w, err)
		return
	}
	h.record(r, user, "server.update.configure", "ok", "token", details)
	respondJSON(w, http.StatusOK, h.Service.Status())
}

func (h *ServerUpdateHandler) check(w http.ResponseWriter, r *http.Request, user *db.UserRow) {
	if err := h.Service.Check(); err != nil {
		h.record(r, user, "server.update.check", err.Error(), "token", nil)
		respondUpdateError(w, err)
		return
	}
	h.record(r, user, "server.update.check", "started", "token", nil)
	respondJSON(w, http.StatusAccepted, h.Service.Status())
}

func (h *ServerUpdateHandler) install(w http.ResponseWriter, r *http.Request, user *db.UserRow) {
	var req struct {
		Version string `json:"version"`
	}
	if !decodeStrict(r, w, &req) || req.Version == "" {
		respondUpdateError(w, errCode("invalid_request"))
		return
	}
	details := map[string]any{"version": req.Version, "from_version": h.Service.Status().CurrentVersion}
	if err := h.Service.Install(req.Version); err != nil {
		h.record(r, user, "server.update.install", err.Error(), "token", details)
		respondUpdateError(w, err)
		return
	}
	h.record(r, user, "server.update.install", "started", "token", details)
	respondJSON(w, http.StatusAccepted, h.Service.Status())
}

// upload accepts a signed update ZIP as the raw request body. It is usable
// with any administrator token, including CLI API keys, so automation can
// deliver development builds; the signature, platform, channel and version
// rules still gate it.
func (h *ServerUpdateHandler) upload(w http.ResponseWriter, r *http.Request, user *db.UserRow) {
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if contentType != "application/zip" && contentType != "application/octet-stream" {
		respondCodedError(w, http.StatusUnsupportedMediaType, "zip_required", "Send the signed update ZIP as application/zip")
		return
	}
	// The server's default read timeout is sized for API calls, not for a
	// binary upload over a slow link.
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(15 * time.Minute))
	body := http.MaxBytesReader(w, r.Body, updater.MaxZIPBytes)
	from := h.Service.Status().CurrentVersion
	version, err := h.Service.Upload(body)
	if err != nil {
		// Drain so the client sees the error code rather than a reset connection.
		_, _ = io.Copy(io.Discard, body)
		h.record(r, user, "server.update.upload", err.Error(), "token", map[string]any{"from_version": from})
		respondUpdateError(w, err)
		return
	}
	h.record(r, user, "server.update.upload", "accepted", "token", map[string]any{"version": version, "from_version": from})
	respondJSON(w, http.StatusAccepted, h.Service.Status())
}

// rollback restores the previous image after re-authentication with the
// administrator's current password. Tokens cannot tell an interactive
// session from an API key here, so the password is the step-up for every
// caller; administrators who sign in only through SSO set a password first.
func (h *ServerUpdateHandler) rollback(w http.ResponseWriter, r *http.Request, user *db.UserRow) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		CurrentVersion  string `json:"current_version"`
		RollbackVersion string `json:"rollback_version"`
	}
	if !decodeStrict(r, w, &req) || req.CurrentVersion == "" || req.RollbackVersion == "" {
		respondUpdateError(w, errCode("invalid_request"))
		return
	}
	details := map[string]any{"from_version": req.CurrentVersion, "to_version": req.RollbackVersion}
	if err := h.Service.RollbackReady(req.CurrentVersion, req.RollbackVersion); err != nil {
		respondUpdateError(w, err)
		return
	}
	if req.CurrentPassword == "" {
		respondCodedError(w, http.StatusForbidden, "RECENT_AUTH_REQUIRED", "current_password is required to roll the server back")
		return
	}
	if !h.reauth.allow(user.ID) {
		h.record(r, user, "server.update.rollback", "REAUTH_RATE_LIMITED", "password", details)
		respondCodedError(w, http.StatusTooManyRequests, "REAUTH_RATE_LIMITED", "Too many failed verifications; try again later")
		return
	}
	if authpkg.CheckPassword(user.PasswordHash, req.CurrentPassword) != nil {
		h.reauth.fail(user.ID)
		h.record(r, user, "server.update.rollback", "REAUTH_FAILED", "password", details)
		respondCodedError(w, http.StatusUnauthorized, "REAUTH_FAILED", "Current password is incorrect")
		return
	}
	h.reauth.succeed(user.ID)
	if err := h.Service.Rollback(req.CurrentVersion, req.RollbackVersion); err != nil {
		h.record(r, user, "server.update.rollback", err.Error(), "password", details)
		respondUpdateError(w, err)
		return
	}
	h.record(r, user, "server.update.rollback", "started", "password", details)
	respondJSON(w, http.StatusAccepted, h.Service.Status())
}

func (h *ServerUpdateHandler) audit(w http.ResponseWriter, r *http.Request, _ *db.UserRow) {
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 500 {
			respondUpdateError(w, errCode("invalid_request"))
			return
		}
		limit = n
	}
	events := []updater.AuditEvent{}
	if h.Auditor != nil {
		recent, err := h.Auditor.Recent(limit)
		if err != nil {
			respondCodedError(w, http.StatusInternalServerError, "audit_unreadable", "The audit log cannot be read")
			return
		}
		events = append(events, recent...)
	}
	respondJSON(w, http.StatusOK, map[string]any{"events": events})
}

type errCode string

func (e errCode) Error() string { return string(e) }

// reauthLimiter allows five failed password verifications per user within
// fifteen minutes.
type reauthLimiter struct {
	mu       sync.Mutex
	failures map[int][]time.Time
}

const (
	reauthMaxFailures = 5
	reauthWindow      = 15 * time.Minute
)

// reauthNow is the limiter clock (tests advance it).
var reauthNow = time.Now

func (l *reauthLimiter) recent(userID int, now time.Time) []time.Time {
	var kept []time.Time
	for _, t := range l.failures[userID] {
		if now.Sub(t) < reauthWindow {
			kept = append(kept, t)
		}
	}
	return kept
}

func (l *reauthLimiter) allow(userID int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(userID, reauthNow())) < reauthMaxFailures
}

func (l *reauthLimiter) fail(userID int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failures == nil {
		l.failures = map[int][]time.Time{}
	}
	now := reauthNow()
	l.failures[userID] = append(l.recent(userID, now), now)
}

func (l *reauthLimiter) succeed(userID int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, userID)
}

// LocalRoutes registers the local upload outside the user authentication:
// GET and POST /api/v1/server/update/local. The caller proves it can read the
// secret file the server wrote into its state directory (service account and
// root only) and must connect over loopback without proxy headers, so the
// route is unreachable through a reverse proxy even with the secret. The
// rules are the admin upload's, except the channel (Service.UploadLocal):
// the host's administrator chose this build. deploy/linux/install.sh
// --build-from-source upgrades through it.
func (h *ServerUpdateHandler) LocalRoutes(r chi.Router) {
	r.Get("/api/v1/server/update/local", h.local(func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, http.StatusOK, h.Service.Status())
	}))
	r.Post("/api/v1/server/update/local", h.local(h.localUpload))
}

func (h *ServerUpdateHandler) local(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		ip := net.ParseIP(host)
		if err != nil || ip == nil || !ip.IsLoopback() || r.Header.Get("Forwarded") != "" ||
			r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("X-Real-Ip") != "" {
			respondCodedError(w, http.StatusForbidden, "local_only", "This route is only available on the host itself")
			return
		}
		got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if h.LocalSecret == "" || subtle.ConstantTimeCompare([]byte(got), []byte(h.LocalSecret)) != 1 {
			h.record(r, nil, "server.update.local", "local_secret_invalid", "local_secret", nil)
			respondCodedError(w, http.StatusUnauthorized, "local_secret_invalid", "Unauthorized")
			return
		}
		next(w, r)
	}
}

func (h *ServerUpdateHandler) localUpload(w http.ResponseWriter, r *http.Request) {
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if contentType != "application/zip" && contentType != "application/octet-stream" {
		respondCodedError(w, http.StatusUnsupportedMediaType, "zip_required", "Send the signed update ZIP as application/zip")
		return
	}
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(15 * time.Minute))
	body := http.MaxBytesReader(w, r.Body, updater.MaxZIPBytes)
	from := h.Service.Status().CurrentVersion
	version, err := h.Service.UploadLocal(body)
	if err != nil {
		_, _ = io.Copy(io.Discard, body)
		h.record(r, nil, "server.update.local_upload", err.Error(), "local_secret", map[string]any{"from_version": from})
		respondUpdateError(w, err)
		return
	}
	h.record(r, nil, "server.update.local_upload", "accepted", "local_secret", map[string]any{"version": version, "from_version": from})
	respondJSON(w, http.StatusAccepted, h.Service.Status())
}
