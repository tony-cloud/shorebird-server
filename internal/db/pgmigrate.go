package db

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

// PostgreSQL schema migrations.
//
// The SQL files in migrations/ are Goose migrations. The server applies the
// missing "Up" sections itself at startup (DB_AUTO_MIGRATE, default on) and
// records them in Goose's own version table, so a database that an operator
// migrated with the goose CLI continues where goose stopped, and goose sees
// what the server applied. SQLite keeps its built-in migrate().

//go:embed migrations/*.sql
var postgresMigrationFiles embed.FS

// gooseTable is goose's default version table.
const gooseTable = "goose_db_version"

// migrationLockID serializes concurrent migrators (pg_advisory_lock key):
// two servers starting against one database never apply a migration twice.
const migrationLockID = 0x5b1d5e7e

// Migration is one embedded Goose migration.
type Migration struct {
	Version int64
	Name    string
	Up      string
}

var migrationName = regexp.MustCompile(`^([0-9]+)_[A-Za-z0-9_]+\.sql$`)

// PostgresMigrations returns the embedded migrations in version order.
func PostgresMigrations() ([]Migration, error) {
	entries, err := postgresMigrationFiles.ReadDir("migrations")
	if err != nil {
		return nil, err
	}
	var migrations []Migration
	seen := map[int64]string{}
	for _, entry := range entries {
		match := migrationName.FindStringSubmatch(entry.Name())
		if match == nil {
			return nil, fmt.Errorf("migration %s: expected NNN_name.sql", entry.Name())
		}
		version, err := strconv.ParseInt(match[1], 10, 64)
		if err != nil || version < 1 {
			return nil, fmt.Errorf("migration %s: invalid version", entry.Name())
		}
		if other, dup := seen[version]; dup {
			return nil, fmt.Errorf("migrations %s and %s share version %d", other, entry.Name(), version)
		}
		seen[version] = entry.Name()
		data, err := postgresMigrationFiles.ReadFile(path.Join("migrations", entry.Name()))
		if err != nil {
			return nil, err
		}
		up, err := gooseUp(string(data))
		if err != nil {
			return nil, fmt.Errorf("migration %s: %w", entry.Name(), err)
		}
		migrations = append(migrations, Migration{Version: version, Name: entry.Name(), Up: up})
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].Version < migrations[j].Version })
	return migrations, nil
}

// gooseUp extracts the Up section of a Goose SQL file. The whole section runs
// as one simple-protocol batch inside the migration's transaction, so the
// StatementBegin/End markers need no special handling; a migration that asks
// for "NO TRANSACTION" is refused (none exists, and running it in a
// transaction would change its meaning).
func gooseUp(text string) (string, error) {
	var up []string
	section := ""
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "-- +goose") {
			switch annotation := strings.Fields(strings.TrimPrefix(trimmed, "-- +goose")); {
			case len(annotation) == 1 && annotation[0] == "Up":
				if section != "" {
					return "", errors.New("unexpected goose Up")
				}
				section = "up"
			case len(annotation) == 1 && annotation[0] == "Down":
				if section != "up" {
					return "", errors.New("goose Down before Up")
				}
				section = "down"
			case len(annotation) == 1 && (annotation[0] == "StatementBegin" || annotation[0] == "StatementEnd"):
			default:
				return "", fmt.Errorf("unsupported goose annotation %q", trimmed)
			}
			continue
		}
		if section == "up" {
			up = append(up, line)
		}
	}
	if section == "" {
		return "", errors.New("no goose Up section")
	}
	body := strings.TrimSpace(strings.Join(up, "\n"))
	if body == "" {
		return "", errors.New("empty goose Up section")
	}
	return body, nil
}

// MigrationResult reports what Migrate did.
type MigrationResult struct {
	Applied []int64 // versions applied by this call
	Current int64   // highest applied version afterwards
}

// Migrate applies every embedded migration the database lacks.
//
// A database that already holds the server schema but no goose version table
// was migrated by some other means; guessing its version could re-run DDL, so
// that is refused with instructions instead.
func (db *PgStore) Migrate(ctx context.Context) (MigrationResult, error) {
	migrations, err := PostgresMigrations()
	if err != nil {
		return MigrationResult{}, err
	}
	conn, err := db.pool.Acquire(ctx)
	if err != nil {
		return MigrationResult{}, err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", int64(migrationLockID)); err != nil {
		return MigrationResult{}, fmt.Errorf("migration lock: %w", err)
	}
	defer conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", int64(migrationLockID)) //nolint:errcheck

	var tableExists, schemaExists bool
	err = conn.QueryRow(ctx, `SELECT
		to_regclass(quote_ident(current_schema()) || '.`+gooseTable+`') IS NOT NULL,
		to_regclass(quote_ident(current_schema()) || '.users') IS NOT NULL`).Scan(&tableExists, &schemaExists)
	if err != nil {
		return MigrationResult{}, fmt.Errorf("inspect schema: %w", err)
	}
	if !tableExists {
		if schemaExists {
			return MigrationResult{}, errors.New("the database holds the server schema but no " + gooseTable +
				" table (migrations applied by hand); record the applied versions in " + gooseTable +
				" (README, \"PostgreSQL schema\") or set DB_AUTO_MIGRATE=off")
		}
		_, err = conn.Exec(ctx, `CREATE TABLE `+gooseTable+` (
			id SERIAL PRIMARY KEY,
			version_id BIGINT NOT NULL,
			is_applied BOOLEAN NOT NULL,
			tstamp TIMESTAMP NOT NULL DEFAULT now());
			INSERT INTO `+gooseTable+` (version_id, is_applied) VALUES (0, true)`)
		if err != nil {
			return MigrationResult{}, fmt.Errorf("create %s: %w", gooseTable, err)
		}
	}
	applied, err := appliedVersions(ctx, conn.Conn())
	if err != nil {
		return MigrationResult{}, err
	}
	var result MigrationResult
	for version := range applied {
		if version > result.Current {
			result.Current = version
		}
	}
	for _, migration := range migrations {
		if applied[migration.Version] {
			continue
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return result, err
		}
		if _, err := tx.Exec(ctx, migration.Up); err != nil {
			_ = tx.Rollback(ctx)
			return result, fmt.Errorf("migration %s: %w", migration.Name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO `+gooseTable+` (version_id, is_applied) VALUES ($1, true)`, migration.Version); err != nil {
			_ = tx.Rollback(ctx)
			return result, fmt.Errorf("record migration %s: %w", migration.Name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return result, fmt.Errorf("migration %s: %w", migration.Name, err)
		}
		result.Applied = append(result.Applied, migration.Version)
		if migration.Version > result.Current {
			result.Current = migration.Version
		}
	}
	return result, nil
}

// appliedVersions follows goose: the newest row of each version decides
// whether it is applied (a "down" adds a row with is_applied false).
func appliedVersions(ctx context.Context, conn *pgx.Conn) (map[int64]bool, error) {
	rows, err := conn.Query(ctx, `SELECT version_id, is_applied FROM `+gooseTable+` ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", gooseTable, err)
	}
	defer rows.Close()
	applied := map[int64]bool{}
	for rows.Next() {
		var version int64
		var isApplied bool
		if err := rows.Scan(&version, &isApplied); err != nil {
			return nil, err
		}
		if version > 0 {
			applied[version] = isApplied
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for version, ok := range applied {
		if !ok {
			delete(applied, version)
		}
	}
	return applied, nil
}
