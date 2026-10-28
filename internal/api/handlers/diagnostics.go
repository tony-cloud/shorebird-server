package handlers

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// These decimal sizes are part of the public CLI's NetworkChecker protocol.
const diagnosticsUploadBytes int64 = 5_000_000
const diagnosticsDownloadBytes int64 = 16_000_000
const diagnosticsGrantLifetime = 5 * time.Minute

type DiagnosticsHandler struct {
	baseURL string
	secret  [32]byte
}

func newDiagnosticsHandler(baseURL string) *DiagnosticsHandler {
	h := &DiagnosticsHandler{baseURL: strings.TrimRight(baseURL, "/")}
	if _, err := rand.Read(h.secret[:]); err != nil {
		panic(fmt.Errorf("diagnostic grant randomness: %w", err))
	}
	return h
}

func (h *DiagnosticsHandler) sign(operation string, expires int64) string {
	mac := hmac.New(sha256.New, h.secret[:])
	fmt.Fprintf(mac, "diagnostics-v1\n%s\n%d", operation, expires)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (h *DiagnosticsHandler) transferURL(r *http.Request, operation string) string {
	base := h.baseURL
	if base == "" {
		// Tests and embedded routers can omit the external URL. Production
		// config supplies SERVER_BASE_URL, including behind TLS proxies.
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		base = scheme + "://" + r.Host
	}
	expires := time.Now().Add(diagnosticsGrantLifetime).Unix()
	return base + "/diagnostics/" + operation + "?" + url.Values{
		"expires": {strconv.FormatInt(expires, 10)},
		"token":   {h.sign(operation, expires)},
	}.Encode()
}

// GCP names are retained for the existing public CLI protocol. Transfers use
// this self-hosted origin and never depend on a Google Cloud service.
func (h *DiagnosticsHandler) GCPUploadSpeedTest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	respondJSON(w, http.StatusOK, map[string]string{"upload_url": h.transferURL(r, "upload")})
}

func (h *DiagnosticsHandler) GCPDownloadSpeedTest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	respondJSON(w, http.StatusOK, map[string]string{"download_url": h.transferURL(r, "download")})
}

func (h *DiagnosticsHandler) authorize(w http.ResponseWriter, r *http.Request, operation string) bool {
	expires, err := strconv.ParseInt(r.URL.Query().Get("expires"), 10, 64)
	if err != nil || expires <= time.Now().Unix() || !hmac.Equal([]byte(r.URL.Query().Get("token")), []byte(h.sign(operation, expires))) {
		respondError(w, http.StatusForbidden, "Invalid or expired diagnostic URL", nil)
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	return true
}

// Upload discards the CLI's five-megabyte multipart probe without storing it.
func (h *DiagnosticsHandler) Upload(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r, "upload") {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, diagnosticsUploadBytes+(64<<10))
	parts, err := r.MultipartReader()
	if err != nil {
		respondError(w, http.StatusBadRequest, "Expected multipart speed-test file", nil)
		return
	}
	part, err := parts.NextPart()
	if err != nil || part.FormName() != "file" || part.FileName() == "" {
		respondError(w, http.StatusBadRequest, "Expected one speed-test file", nil)
		return
	}
	defer part.Close()
	size, err := io.Copy(io.Discard, io.LimitReader(part, diagnosticsUploadBytes+1))
	if err != nil || size != diagnosticsUploadBytes {
		respondError(w, http.StatusBadRequest, "Speed-test file must be exactly 5000000 bytes", nil)
		return
	}
	if _, err := parts.NextPart(); err != io.EOF {
		respondError(w, http.StatusBadRequest, "Expected one speed-test file", nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type diagnosticsZeroReader struct{}

func (diagnosticsZeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func (h *DiagnosticsHandler) Download(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r, "download") {
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(diagnosticsDownloadBytes, 10))
	_, _ = io.CopyN(w, diagnosticsZeroReader{}, diagnosticsDownloadBytes)
}
