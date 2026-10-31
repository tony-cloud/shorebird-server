package db

import (
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestPatchEventMetadataSQLiteForwardMigration(t *testing.T) {
	path := t.TempDir() + "/legacy.db"
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`CREATE TABLE patch_events (id INTEGER PRIMARY KEY AUTOINCREMENT, app_id TEXT NOT NULL, client_id TEXT NOT NULL, arch TEXT NOT NULL, patch_number INTEGER NOT NULL, platform TEXT NOT NULL, release_version TEXT NOT NULL, event_type TEXT NOT NULL, timestamp INTEGER NOT NULL, message TEXT, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')))`)
	if err != nil {
		legacy.Close()
		t.Fatal(err)
	}
	appID := uuid.New()
	for i := 0; i < 2; i++ {
		_, err := legacy.Exec(`INSERT INTO patch_events (app_id, client_id, arch, patch_number, platform, release_version, event_type, timestamp, message) VALUES (?, 'legacy-client', 'aarch64', 1, 'ios', '1.0.0+1', 'PatchInstallFailure', 1234, 'legacy message')`, appID.String())
		if err != nil {
			legacy.Close()
			t.Fatal(err)
		}
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := NewSqliteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := store.ListPatchEvents(t.Context(), appID, 0, 10)
	if err != nil || len(rows) != 2 {
		store.Close()
		t.Fatalf("legacy rows lost: %+v, %v", rows, err)
	}
	for _, row := range rows {
		if row.EventID != nil || row.FailureCategory != nil || row.Type != "PatchInstallFailure" || row.Message == nil || *row.Message != "legacy message" {
			store.Close()
			t.Fatalf("legacy row changed during migration: %+v", row)
		}
	}
	eventID, category := uuid.NewString(), "network"
	metadata := &PatchEventMetadata{EventID: &eventID, FailureCategory: &category}
	for i := 0; i < 2; i++ {
		if err := store.InsertPatchEvent(t.Context(), appID, "new-client", "aarch64", "ios", "1.0.0+1", "__patch_update_failure__", 1, 1234, nil, metadata); err != nil {
			store.Close()
			t.Fatal(err)
		}
	}
	store.Close()
	reopened, err := NewSqliteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reopened.Close)
	rows, err = reopened.ListPatchEvents(t.Context(), appID, 0, 10)
	if err != nil || len(rows) != 3 || rows[0].EventID == nil || *rows[0].EventID != eventID || rows[0].FailureCategory == nil || *rows[0].FailureCategory != category {
		t.Fatalf("metadata migration was not durable/idempotent: %+v, %v", rows, err)
	}
}

func TestPatchEventMetadataPostgresForwardMigration(t *testing.T) {
	dsn := os.Getenv("SHOREBIRD_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set SHOREBIRD_TEST_POSTGRES_DSN to an isolated migrated PostgreSQL database")
	}
	connection, err := pgx.Connect(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(t.Context())
	// A connection-owned temporary table isolates the forward-migration test
	// from the schema used by the HTTP integration suite.
	_, err = connection.Exec(t.Context(), `CREATE TEMP TABLE patch_events (id SERIAL PRIMARY KEY, app_id UUID NOT NULL, client_id TEXT NOT NULL, arch TEXT NOT NULL, patch_number INTEGER NOT NULL, platform TEXT NOT NULL, release_version TEXT NOT NULL, event_type TEXT NOT NULL, timestamp BIGINT NOT NULL, message JSONB, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()); SET search_path TO pg_temp`)
	if err != nil {
		t.Fatal(err)
	}
	appID := uuid.New()
	for i := 0; i < 2; i++ {
		_, err := connection.Exec(t.Context(), `INSERT INTO patch_events (app_id, client_id, arch, patch_number, platform, release_version, event_type, timestamp) VALUES ($1, 'legacy-client', 'aarch64', 1, 'ios', '1.0.0+1', 'PatchInstallSuccess', 1234)`, appID)
		if err != nil {
			t.Fatal(err)
		}
	}
	migration, err := os.ReadFile("migrations/004_patch_event_metadata.sql")
	if err != nil {
		t.Fatal(err)
	}
	up := strings.Split(string(migration), "-- +goose Down")[0]
	if _, err := connection.Exec(t.Context(), up); err != nil {
		t.Fatal(err)
	}
	var legacyCount int
	if err := connection.QueryRow(t.Context(), `SELECT COUNT(*) FROM patch_events WHERE event_id IS NULL AND failure_category IS NULL AND event_type = 'PatchInstallSuccess'`).Scan(&legacyCount); err != nil || legacyCount != 2 {
		t.Fatalf("legacy PostgreSQL rows changed: count %d, err %v", legacyCount, err)
	}
	eventID := uuid.New()
	query := `INSERT INTO patch_events (app_id, client_id, arch, patch_number, platform, release_version, event_type, timestamp, event_id, failure_category) VALUES ($1, 'new-client', 'aarch64', 1, 'ios', '1.0.0+1', '__patch_update_failure__', 1234, $2, 'network')`
	if _, err := connection.Exec(t.Context(), query, appID, eventID); err != nil {
		t.Fatal(err)
	}
	_, err = connection.Exec(t.Context(), query, appID, eventID)
	var duplicate *pgconn.PgError
	if !errors.As(err, &duplicate) || duplicate.Code != "23505" {
		t.Fatalf("migration did not establish atomic uniqueness: %v", err)
	}
	if _, err := connection.Exec(t.Context(), query, uuid.New(), eventID); err != nil {
		t.Fatalf("migration incorrectly deduplicates across apps: %v", err)
	}
}
