package handlers

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/shorebird-server/internal/storage"
)

const maxStorageUploadBytes = storage.MaxUploadBytes
const maxMultipartOverheadBytes int64 = 1 << 20

// StorageHandler provides upload/download endpoints for local storage.
type StorageHandler struct {
	store storage.Store
}

// NewStorageHandler creates a new storage HTTP handler.
func NewStorageHandler(store storage.Store) *StorageHandler {
	return &StorageHandler{store: store}
}

// Upload handles POST /storage/upload/{scope}/{key}
func (h *StorageHandler) Upload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxStorageUploadBytes+maxMultipartOverheadBytes)
	scope := chi.URLParam(r, "scope")
	key := chi.URLParam(r, "*")
	if !validStorageUploadScope(scope) {
		respondError(w, http.StatusNotFound, "Unknown storage scope", nil)
		return
	}
	var grantedSize []int64
	if raw := r.URL.Query().Get("size"); raw != "" {
		size, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || size <= 0 || size > maxStorageUploadBytes {
			respondError(w, http.StatusForbidden, "Invalid upload size grant", nil)
			return
		}
		grantedSize = []int64{size}
	}
	validator, ok := h.store.(interface {
		ValidateUploadToken(scope, objectKey, token string, expires int64, size ...int64) bool
	})
	expires, _ := strconv.ParseInt(r.URL.Query().Get("expires"), 10, 64)
	if !ok || !validator.ValidateUploadToken(scope, key, r.URL.Query().Get("token"), expires, grantedSize...) {
		respondError(w, http.StatusForbidden, "Invalid or expired upload URL", nil)
		return
	}

	if len(grantedSize) > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, grantedSize[0]+maxMultipartOverheadBytes)
	}
	isPublic := scope == "patches"
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/octet-stream"
	}

	body := io.Reader(r.Body)
	size := r.ContentLength
	if strings.HasPrefix(ct, "multipart/form-data") {
		parts, err := r.MultipartReader()
		if err != nil {
			respondError(w, http.StatusBadRequest, "Invalid multipart upload", nil)
			return
		}
		for {
			part, err := parts.NextPart()
			if err != nil {
				respondError(w, http.StatusBadRequest, "Upload failed: missing multipart file", nil)
				return
			}
			if part.FormName() != "file" {
				part.Close()
				continue
			}
			defer part.Close()
			body = part
			ct = part.Header.Get("Content-Type")
			if ct == "" {
				ct = "application/octet-stream"
			}
			size = -1
			break
		}
	}
	if len(grantedSize) > 0 {
		size = grantedSize[0]
		body = &exactUploadReader{reader: body, remaining: size}
	}

	if err := h.store.UploadObject(r.Context(), key, body, size, ct, isPublic); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errUploadSizeMismatch) || errors.Is(err, io.ErrUnexpectedEOF) {
			status = http.StatusBadRequest
		}
		var limitError *http.MaxBytesError
		if errors.As(err, &limitError) {
			status = http.StatusRequestEntityTooLarge
		}
		respondError(w, status, "Upload failed", nil)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// Download handles GET /storage/dl/{scope}/{key}
func (h *StorageHandler) Download(w http.ResponseWriter, r *http.Request) {
	scope := chi.URLParam(r, "scope")
	key := chi.URLParam(r, "*")
	if scope != "releases" && scope != "patches" {
		respondError(w, http.StatusNotFound, "Unknown storage scope", nil)
		return
	}
	validator, ok := h.store.(interface {
		ValidateDownloadToken(scope, objectKey, token string, expires int64) bool
	})
	expires, _ := strconv.ParseInt(r.URL.Query().Get("expires"), 10, 64)
	if !ok || !validator.ValidateDownloadToken(scope, key, r.URL.Query().Get("token"), expires) {
		respondError(w, http.StatusForbidden, "Invalid or expired download URL", nil)
		return
	}

	isPublic := scope == "patches"

	reader, err := h.store.GetObject(r.Context(), key, isPublic)
	if err != nil {
		respondError(w, http.StatusNotFound, "File not found", nil)
		return
	}
	defer reader.Close()

	contentType := "application/octet-stream"
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Accept-Ranges", "bytes")
	io.Copy(w, reader)
}

func validStorageUploadScope(scope string) bool { return scope == "releases" || scope == "patches" }
