package handlers

import (
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/shorebird-server/internal/storage"
)

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
	scope := chi.URLParam(r, "scope")
	key := chi.URLParam(r, "*")

	isPublic := scope == "patches"
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/octet-stream"
	}

	body := io.Reader(r.Body)
	size := r.ContentLength
	if strings.HasPrefix(ct, "multipart/form-data") {
		file, header, err := r.FormFile("file")
		if err != nil {
			respondError(w, http.StatusBadRequest, "Upload failed: missing multipart file", nil)
			return
		}
		defer file.Close()
		body = file
		size = header.Size
		ct = header.Header.Get("Content-Type")
		if ct == "" {
			ct = "application/octet-stream"
		}
	}

	if err := h.store.UploadObject(r.Context(), key, body, size, ct, isPublic); err != nil {
		respondError(w, http.StatusInternalServerError, "Upload failed: "+err.Error(), nil)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// Download handles GET /storage/dl/{scope}/{key}
func (h *StorageHandler) Download(w http.ResponseWriter, r *http.Request) {
	scope := chi.URLParam(r, "scope")
	key := chi.URLParam(r, "*")
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
