package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAPISpecRoutes(t *testing.T) {
	router := NewRouter(nil, nil, nil, nil, "", PatchDeliveryConfig{})

	for _, path := range []string{"/openapi.yaml", "/api/v1/openapi.yaml"} {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, path, nil)
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
			}
			if contentType := response.Header().Get("Content-Type"); !strings.Contains(contentType, "application/yaml") {
				t.Fatalf("Content-Type = %q, want application/yaml", contentType)
			}
			body := response.Body.String()
			for _, required := range []string{
				"openapi: 3.1.0",
				"/api/v1/patches/check:",
				"/openapi.yaml:",
			} {
				if !strings.Contains(body, required) {
					t.Fatalf("spec body missing %q", required)
				}
			}
		})
	}
}
