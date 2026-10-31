package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"
	"github.com/shorebird-server/internal/models"
)

const maxPatchEventRequestBytes = 256 * 1024

func decodePatchEventRequest(w http.ResponseWriter, r *http.Request, request *models.CreatePatchEventRequest) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxPatchEventRequestBytes)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(request); err != nil {
		return err
	}
	// Read through EOF to enforce the body bound even with trailing whitespace
	// or unknown fields; accept exactly one JSON request.
	if err := decoder.Decode(new(interface{})); err != io.EOF {
		if err != nil {
			return err
		}
		return errors.New("multiple JSON values")
	}
	return nil
}

func validatePatchEventFields(event *models.PatchEvent) error {
	for _, field := range []struct {
		name, value string
		max         int
	}{
		{"client_id", event.ClientID, 256},
		{"arch", event.Arch, 64},
		{"platform", event.Platform, 64},
		{"release_version", event.ReleaseVersion, 1024},
	} {
		if len(field.value) > field.max {
			return fmt.Errorf("%s exceeds %d bytes", field.name, field.max)
		}
	}
	if event.Message != nil && len(*event.Message) > 32*1024 {
		return errors.New("message exceeds 32 KiB")
	}
	// Match the native unsigned values and the common PostgreSQL INTEGER
	// patch-number storage range, rather than surfacing an insertion failure.
	if event.PatchNumber < 0 || int64(event.PatchNumber) > 2147483647 || event.Timestamp < 0 {
		return errors.New("invalid patch_number or timestamp")
	}
	if event.EventID != nil {
		if len(*event.EventID) != 36 {
			return errors.New("event_id must be a UUID")
		}
		id, err := uuid.Parse(*event.EventID)
		if err != nil || id == uuid.Nil {
			return errors.New("event_id must be a nonzero UUID")
		}
		if event.ClientID == "" {
			return errors.New("client_id is required with event_id")
		}
		canonical := id.String()
		event.EventID = &canonical
	}
	if event.FailureCategory != nil {
		category := *event.FailureCategory
		if len(category) == 0 || len(category) > 128 {
			return errors.New("failure_category must contain 1 to 128 identifier bytes")
		}
		// Keep the category vocabulary open for newer updater versions while
		// excluding whitespace, control characters, and free-form diagnostics.
		for _, c := range []byte(category) {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' {
				continue
			}
			return errors.New("failure_category must be an ASCII identifier")
		}
	}
	return nil
}
