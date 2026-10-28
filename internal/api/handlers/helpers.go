package handlers

import (
	"encoding/json"
	"net/http"
)

// respondJSON writes a JSON response with the given status code.
func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

// respondError writes a JSON error response.
func respondError(w http.ResponseWriter, status int, message string, details *string) {
	respondJSON(w, status, map[string]interface{}{
		"message": message,
		"details": details,
	})
}

// decodeJSON decodes a JSON request body.
func decodeJSON(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

// respondCodedError gives clients a stable machine-readable capability error.
func respondCodedError(w http.ResponseWriter, status int, code, message string) {
	respondJSON(w, status, map[string]interface{}{"code": code, "message": message, "details": nil})
}
