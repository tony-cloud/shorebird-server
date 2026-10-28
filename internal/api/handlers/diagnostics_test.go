package handlers

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestDiagnosticsHTTPMatchesPublicDartClientProtocol(t *testing.T) {
	f := newAPIFixture(t)
	for _, operation := range []string{"upload", "download"} {
		api := "/api/v1/diagnostics/gcp_" + operation
		status, _ := f.request(t, http.MethodGet, api, "", "", "")
		if status != http.StatusUnauthorized {
			t.Fatalf("unauthenticated diagnostics: %d", status)
		}
		status, data := f.request(t, http.MethodGet, api, f.owner, "", "")
		if status != http.StatusOK {
			t.Fatalf("diagnostics URL %d %s", status, data)
		}
		var response map[string]string
		if err := json.Unmarshal(data, &response); err != nil {
			t.Fatal(err)
		}
		transfer, err := url.Parse(response[operation+"_url"])
		if err != nil || transfer.Host == "example.com" || transfer.Path != "/diagnostics/"+operation || transfer.Query().Get("token") == "" {
			t.Fatalf("not a scoped same-server transfer URL: %s", data)
		}
		if operation == "download" {
			status, data := f.request(t, http.MethodGet, transfer.RequestURI(), "", "", "")
			if status != http.StatusOK || int64(len(data)) != diagnosticsDownloadBytes {
				t.Fatalf("download result: status=%d size=%d", status, len(data))
			}
			continue
		}
		for _, size := range []int64{diagnosticsUploadBytes, diagnosticsUploadBytes - 1, diagnosticsUploadBytes + 1} {
			var body bytes.Buffer
			writer := multipart.NewWriter(&body)
			part, err := writer.CreateFormFile("file", "speed_test_file")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.CopyN(part, diagnosticsZeroReader{}, size); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			status, data := f.request(t, http.MethodPost, transfer.RequestURI(), "", writer.FormDataContentType(), body.String())
			want := http.StatusBadRequest
			if size == diagnosticsUploadBytes {
				want = http.StatusNoContent
			}
			if status != want {
				t.Fatalf("upload size %d: got %d want %d: %s", size, status, want, data)
			}
		}
		// A transfer URL cannot be changed into the other operation.
		transfer.Path = "/diagnostics/download"
		status, _ = f.request(t, http.MethodGet, transfer.RequestURI(), "", "", "")
		if status != http.StatusForbidden {
			t.Fatalf("cross-operation grant accepted: %d", status)
		}
	}
}

func TestDiagnosticTransferRejectsMissingExpiredAndTamperedGrants(t *testing.T) {
	h := newDiagnosticsHandler("https://updates.test")
	for _, operation := range []string{"upload", "download"} {
		for _, kind := range []string{"missing", "expired", "tampered"} {
			expires := time.Now().Add(time.Minute).Unix()
			if kind == "expired" {
				expires = time.Now().Add(-time.Minute).Unix()
			}
			grant := h.sign(operation, expires)
			if kind == "missing" {
				grant = ""
			}
			if kind == "tampered" {
				grant += "x"
			}
			request := httptest.NewRequest(http.MethodGet, "/diagnostics/"+operation+"?expires="+strconv.FormatInt(expires, 10)+"&token="+url.QueryEscape(grant), nil)
			response := httptest.NewRecorder()
			if operation == "upload" {
				h.Upload(response, request)
			} else {
				h.Download(response, request)
			}
			if response.Code != http.StatusForbidden {
				t.Fatalf("%s %s: %d", operation, kind, response.Code)
			}
		}
	}
}
