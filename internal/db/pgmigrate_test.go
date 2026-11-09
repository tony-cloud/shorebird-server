package db

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestPostgresMigrationsParse(t *testing.T) {
	migrations, err := PostgresMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if len(migrations) < 5 {
		t.Fatalf("expected the embedded migrations, got %d", len(migrations))
	}
	for i, migration := range migrations {
		if migration.Version != int64(i+1) {
			t.Fatalf("migration versions must be contiguous: %s is %d", migration.Name, migration.Version)
		}
		if strings.Contains(migration.Up, "+goose") || strings.Contains(strings.ToUpper(migration.Up), "DROP TABLE") {
			t.Fatalf("%s: the Up section leaked annotations or the Down section", migration.Name)
		}
	}
}

func TestGooseUpRefusals(t *testing.T) {
	for name, text := range map[string]string{
		"no up":          "CREATE TABLE x();",
		"down first":     "-- +goose Down\nDROP TABLE x;\n-- +goose Up\nCREATE TABLE x();",
		"no transaction": "-- +goose NO TRANSACTION\n-- +goose Up\nCREATE INDEX CONCURRENTLY i ON x(y);",
		"empty":          "-- +goose Up\n-- +goose Down\nDROP TABLE x;",
		"two ups":        "-- +goose Up\nSELECT 1;\n-- +goose Up\nSELECT 2;",
	} {
		if _, err := gooseUp(text); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	up, err := gooseUp("-- +goose Up\n-- +goose StatementBegin\nCREATE TABLE x();\n-- +goose StatementEnd\n-- +goose Down\nDROP TABLE x;\n")
	if err != nil || up != "CREATE TABLE x();" {
		t.Fatalf("got %q, %v", up, err)
	}
}

// postgresSchema returns a store confined to a fresh schema of
// SHOREBIRD_TEST_POSTGRES_DSN, dropped after the test.
func postgresSchema(t *testing.T) (*PgStore, *pgx.Conn, string) {
	t.Helper()
	dsn := os.Getenv("SHOREBIRD_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set SHOREBIRD_TEST_POSTGRES_DSN to a PostgreSQL database for migration tests")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "migrate_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		_ = admin.Close(context.Background())
	})
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	store, err := NewPostgresStore(ctx, dsn+sep+"search_path="+schema)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	return store, admin, schema
}

func TestPostgresMigrateFreshIdempotentAndUsable(t *testing.T) {
	store, admin, schema := postgresSchema(t)
	ctx := context.Background()
	migrations, _ := PostgresMigrations()
	result, err := store.Migrate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Applied) != len(migrations) || result.Current != migrations[len(migrations)-1].Version {
		t.Fatalf("fresh database: %+v", result)
	}
	again, err := store.Migrate(ctx)
	if err != nil || len(again.Applied) != 0 || again.Current != result.Current {
		t.Fatalf("rerun applied something: %+v, %v", again, err)
	}
	var rows int
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM "+schema+".goose_db_version WHERE version_id > 0 AND is_applied").Scan(&rows); err != nil || rows != len(migrations) {
		t.Fatalf("goose version rows: %d, %v", rows, err)
	}
	// The schema serves the store: the bootstrap administrator can be created.
	created, err := store.EnsureDefaultAdmin(ctx, "admin@example.com", "Admin", "hash")
	if err != nil || !created {
		t.Fatalf("EnsureDefaultAdmin on the migrated schema: %v, %v", created, err)
	}
}

func TestPostgresMigrateContinuesAfterGoose(t *testing.T) {
	store, admin, schema := postgresSchema(t)
	ctx := context.Background()
	migrations, _ := PostgresMigrations()
	// An operator ran goose up to version 2, then rolled version 2 back down and up again.
	if _, err := admin.Exec(ctx, "SET search_path TO "+schema); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `CREATE TABLE goose_db_version (id SERIAL PRIMARY KEY, version_id BIGINT NOT NULL, is_applied BOOLEAN NOT NULL, tstamp TIMESTAMP DEFAULT now());
		INSERT INTO goose_db_version (version_id, is_applied) VALUES (0, true), (1, true), (2, true), (2, false), (2, true)`); err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations[:2] {
		if _, err := admin.Exec(ctx, migration.Up); err != nil {
			t.Fatal(err)
		}
	}
	result, err := store.Migrate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Applied) != len(migrations)-2 || result.Applied[0] != 3 {
		t.Fatalf("expected versions 3.. only: %+v", result)
	}
}

func TestPostgresMigrateRefusesUnversionedSchema(t *testing.T) {
	store, admin, schema := postgresSchema(t)
	ctx := context.Background()
	if _, err := admin.Exec(ctx, "CREATE TABLE "+schema+".users (id SERIAL PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	_, err := store.Migrate(ctx)
	if err == nil || !strings.Contains(err.Error(), "DB_AUTO_MIGRATE=off") {
		t.Fatalf("expected a refusal, got %v", err)
	}
	var exists bool
	if err := admin.QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", schema+".goose_db_version").Scan(&exists); err != nil || exists {
		t.Fatalf("the refusal must not create the version table: %v, %v", exists, err)
	}
}
