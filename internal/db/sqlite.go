package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// SqliteStore implements Store backed by a local SQLite database.
type SqliteStore struct {
	db *sql.DB
}

// NewSqliteStore opens (or creates) a SQLite database at the given path.
func NewSqliteStore(path string) (*SqliteStore, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("sqlite: %w", err)
	}

	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	db.SetMaxOpenConns(1)

	store := &SqliteStore{db: db}
	if err := store.migrate(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite: migrate: %w", err)
	}
	return store, nil
}

func (s *SqliteStore) Close() { s.db.Close() }

// --- Users ---
func (s *SqliteStore) CreateUser(ctx context.Context, email, name, passwordHash string) (int, error) {
	var id int
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO users (email, name, password_hash) VALUES (?, ?, ?) RETURNING id`,
		email, name, passwordHash).Scan(&id)
	return id, err
}
func (s *SqliteStore) GetUserByEmail(ctx context.Context, email string) (*UserRow, error) {
	r := &UserRow{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, name, password_hash, created_at FROM users WHERE email = ?`, email).
		Scan(&r.ID, &r.Email, &r.Name, &r.PasswordHash, &r.CreatedAt)
	if err != nil { return nil, err }
	return r, nil
}
func (s *SqliteStore) GetUserByID(ctx context.Context, id int) (*UserRow, error) {
	r := &UserRow{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, name, password_hash, created_at FROM users WHERE id = ?`, id).
		Scan(&r.ID, &r.Email, &r.Name, &r.PasswordHash, &r.CreatedAt)
	if err != nil { return nil, err }
	return r, nil
}
func (s *SqliteStore) ListAllUsers(ctx context.Context) ([]UserListRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT u.id, u.email, u.name, u.created_at, COALESCE(GROUP_CONCAT(DISTINCT om.role), '') FROM users u LEFT JOIN organization_memberships om ON u.id = om.user_id GROUP BY u.id ORDER BY u.created_at DESC`)
	if err != nil { return nil, err }
	defer rows.Close()
	var result []UserListRow
	for rows.Next() {
		var r UserListRow
		if err := rows.Scan(&r.ID, &r.Email, &r.Name, &r.CreatedAt, &r.Role); err != nil { return nil, err }
		result = append(result, r)
	}
	return result, nil
}

// --- Organizations ---
func (s *SqliteStore) CreateOrganization(ctx context.Context, name, orgType string) (int, error) {
	var id int
	err := s.db.QueryRowContext(ctx, `INSERT INTO organizations (name, type) VALUES (?, ?) RETURNING id`, name, orgType).Scan(&id)
	return id, err
}
func (s *SqliteStore) GetOrganizationsByUserID(ctx context.Context, userID int) ([]OrgMembershipRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT o.id, o.name, o.type, om.role FROM organizations o JOIN organization_memberships om ON o.id = om.organization_id WHERE om.user_id = ? ORDER BY o.name`, userID)
	if err != nil { return nil, err }
	defer rows.Close()
	var result []OrgMembershipRow
	for rows.Next() {
		var r OrgMembershipRow
		if err := rows.Scan(&r.OrgID, &r.OrgName, &r.OrgType, &r.Role); err != nil { return nil, err }
		result = append(result, r)
	}
	return result, nil
}
func (s *SqliteStore) AddUserToOrganization(ctx context.Context, userID, orgID int, role string) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO organization_memberships (user_id, organization_id, role) VALUES (?, ?, ?)`, userID, orgID, role)
	return err
}

// --- Apps ---
// rfcNow returns the current UTC time in RFC3339Nano format for SQLite storage.
func rfcNow() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func (s *SqliteStore) CreateApp(ctx context.Context, orgID int, displayName string) (*AppRow, error) {
	id := uuid.New().String()
	now := rfcNow()
	_, err := s.db.ExecContext(ctx, `INSERT INTO apps (id, organization_id, display_name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`, id, orgID, displayName, now, now)
	if err != nil { return nil, err }
	uid, _ := uuid.Parse(id)
	t := time.Now().UTC()
	return &AppRow{ID: uid, OrganizationID: orgID, DisplayName: displayName, CreatedAt: ShorebirdTime{Time: t}, UpdatedAt: ShorebirdTime{Time: t}}, nil
}
func (s *SqliteStore) GetAppsByOrganization(ctx context.Context, orgID int) ([]AppRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, organization_id, display_name, created_at, updated_at FROM apps WHERE organization_id = ? ORDER BY display_name`, orgID)
	if err != nil { return nil, err }
	defer rows.Close()
	return scanApps(rows)
}
func (s *SqliteStore) GetAppByID(ctx context.Context, appID uuid.UUID) (*AppRow, error) {
	r := &AppRow{}
	var idStr string
	err := s.db.QueryRowContext(ctx, `SELECT id, organization_id, display_name, created_at, updated_at FROM apps WHERE id = ?`, appID.String()).
		Scan(&idStr, &r.OrganizationID, &r.DisplayName, &r.CreatedAt, &r.UpdatedAt)
	if err != nil { return nil, err }
	r.ID, _ = uuid.Parse(idStr)
	return r, nil
}
func (s *SqliteStore) GetAppByIDString(ctx context.Context, appID string) (*AppRow, error) {
	id, err := uuid.Parse(appID)
	if err != nil { return nil, fmt.Errorf("invalid app_id: %w", err) }
	return s.GetAppByID(ctx, id)
}
func (s *SqliteStore) DeleteApp(ctx context.Context, appID uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM apps WHERE id = ?`, appID.String())
	return err
}
func (s *SqliteStore) GetAppsByUserID(ctx context.Context, userID int) ([]AppRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT a.id, a.organization_id, a.display_name, a.created_at, a.updated_at FROM apps a JOIN organization_memberships om ON a.organization_id = om.organization_id WHERE om.user_id = ? ORDER BY a.display_name`, userID)
	if err != nil { return nil, err }
	defer rows.Close()
	return scanApps(rows)
}
func scanApps(rows *sql.Rows) ([]AppRow, error) {
	var result []AppRow
	for rows.Next() {
		var r AppRow
		var idStr string
		if err := rows.Scan(&idStr, &r.OrganizationID, &r.DisplayName, &r.CreatedAt, &r.UpdatedAt); err != nil { return nil, err }
		r.ID, _ = uuid.Parse(idStr)
		result = append(result, r)
	}
	return result, nil
}

// --- Channels ---
func (s *SqliteStore) CreateChannel(ctx context.Context, appID uuid.UUID, name string) (*ChannelRow, error) {
	r := &ChannelRow{AppID: appID, Name: name}
	err := s.db.QueryRowContext(ctx, `INSERT INTO channels (app_id, name) VALUES (?, ?) RETURNING id, created_at`, appID.String(), name).Scan(&r.ID, &r.CreatedAt)
	if err != nil { return nil, err }
	return r, nil
}
func (s *SqliteStore) GetChannelsByAppID(ctx context.Context, appID uuid.UUID) ([]ChannelRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, app_id, name, created_at FROM channels WHERE app_id = ? ORDER BY name`, appID.String())
	if err != nil { return nil, err }
	defer rows.Close()
	var result []ChannelRow
	for rows.Next() {
		var r ChannelRow; var aid string
		if err := rows.Scan(&r.ID, &aid, &r.Name, &r.CreatedAt); err != nil { return nil, err }
		r.AppID, _ = uuid.Parse(aid); result = append(result, r)
	}
	return result, nil
}
func (s *SqliteStore) GetChannelByAppIDAndName(ctx context.Context, appID uuid.UUID, name string) (*ChannelRow, error) {
	r := &ChannelRow{}
	var aid string
	err := s.db.QueryRowContext(ctx, `SELECT id, app_id, name, created_at FROM channels WHERE app_id = ? AND name = ?`, appID.String(), name).Scan(&r.ID, &aid, &r.Name, &r.CreatedAt)
	if err != nil { return nil, err }
	r.AppID, _ = uuid.Parse(aid)
	return r, nil
}

// --- Releases ---
func (s *SqliteStore) CreateRelease(ctx context.Context, appID uuid.UUID, version, flutterRevision string, flutterVersion, displayName *string) (*ReleaseRow, error) {
	r := &ReleaseRow{AppID: appID, Version: version, FlutterRevision: flutterRevision, FlutterVersion: flutterVersion, DisplayName: displayName}
	var fv, dn interface{}; if flutterVersion != nil { fv = *flutterVersion }; if displayName != nil { dn = *displayName }
	err := s.db.QueryRowContext(ctx, `INSERT INTO releases (app_id, version, flutter_revision, flutter_version, display_name) VALUES (?, ?, ?, ?, ?) RETURNING id, notes, created_at, updated_at`, appID.String(), version, flutterRevision, fv, dn).Scan(&r.ID, &r.Notes, &r.CreatedAt, &r.UpdatedAt)
	if err != nil { return nil, err }
	return r, nil
}
func (s *SqliteStore) GetReleaseByID(ctx context.Context, releaseID int) (*ReleaseRow, error) {
	r := &ReleaseRow{}
	var aid string
	err := s.db.QueryRowContext(ctx, `SELECT id, app_id, version, flutter_revision, flutter_version, display_name, notes, created_at, updated_at FROM releases WHERE id = ?`, releaseID).Scan(&r.ID, &aid, &r.Version, &r.FlutterRevision, &r.FlutterVersion, &r.DisplayName, &r.Notes, &r.CreatedAt, &r.UpdatedAt)
	if err != nil { return nil, err }
	r.AppID, _ = uuid.Parse(aid)
	return r, nil
}
func (s *SqliteStore) GetReleaseByAppIDAndVersion(ctx context.Context, appID uuid.UUID, version string) (*ReleaseRow, error) {
	r := &ReleaseRow{}
	var aid string
	err := s.db.QueryRowContext(ctx, `SELECT id, app_id, version, flutter_revision, flutter_version, display_name, notes, created_at, updated_at FROM releases WHERE app_id = ? AND version = ?`, appID.String(), version).Scan(&r.ID, &aid, &r.Version, &r.FlutterRevision, &r.FlutterVersion, &r.DisplayName, &r.Notes, &r.CreatedAt, &r.UpdatedAt)
	if err != nil { return nil, err }
	r.AppID, _ = uuid.Parse(aid)
	return r, nil
}
func (s *SqliteStore) GetReleasesByAppID(ctx context.Context, appID uuid.UUID, sideloadableOnly bool) ([]ReleaseRow, error) {
	_ = sideloadableOnly
	rows, err := s.db.QueryContext(ctx, `SELECT id, app_id, version, flutter_revision, flutter_version, display_name, notes, created_at, updated_at FROM releases WHERE app_id = ? ORDER BY created_at DESC`, appID.String())
	if err != nil { return nil, err }
	defer rows.Close()
	var result []ReleaseRow
	for rows.Next() {
		var r ReleaseRow; var aid string
		if err := rows.Scan(&r.ID, &aid, &r.Version, &r.FlutterRevision, &r.FlutterVersion, &r.DisplayName, &r.Notes, &r.CreatedAt, &r.UpdatedAt); err != nil { return nil, err }
		r.AppID, _ = uuid.Parse(aid); result = append(result, r)
	}
	return result, nil
}
func (s *SqliteStore) UpdateReleasePlatformStatus(ctx context.Context, releaseID int, platform, status string, metadata map[string]interface{}) error {
	metaJSON := "{}"
	if metadata != nil { b, _ := json.Marshal(metadata); metaJSON = string(b) }
	_, err := s.db.ExecContext(ctx, `INSERT INTO release_platform_statuses (release_id, platform, status, metadata, updated_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(release_id, platform) DO UPDATE SET status=excluded.status, metadata=excluded.metadata, updated_at=excluded.updated_at`, releaseID, platform, status, metaJSON, rfcNow())
	return err
}
func (s *SqliteStore) GetReleasePlatformStatuses(ctx context.Context, releaseID int) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT platform, status FROM release_platform_statuses WHERE release_id = ?`, releaseID)
	if err != nil { return nil, err }
	defer rows.Close()
	result := make(map[string]string)
	for rows.Next() { var p, st string; if err := rows.Scan(&p, &st); err != nil { return nil, err }; result[p] = st }
	return result, nil
}

// --- Release Artifacts ---
func (s *SqliteStore) CreateReleaseArtifact(ctx context.Context, releaseID int, arch, platform, hash, storageKey string, size int64, canSideload bool, podfileLockHash *string) (*ArtifactRow, error) {
	r := &ArtifactRow{ReleaseID: releaseID, Arch: arch, Platform: platform, Hash: hash, Size: size, StorageKey: storageKey, CanSideload: canSideload, PodfileLockHash: podfileLockHash}
	err := s.db.QueryRowContext(ctx, `INSERT INTO release_artifacts (release_id, arch, platform, hash, size, storage_key, can_sideload, podfile_lock_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id, created_at`, releaseID, arch, platform, hash, size, storageKey, canSideload, podfileLockHash).Scan(&r.ID, &r.CreatedAt)
	if err != nil { return nil, err }
	return r, nil
}
func (s *SqliteStore) GetReleaseArtifacts(ctx context.Context, releaseID int, arch, platform *string) ([]ArtifactRow, error) {
	query := `SELECT id, release_id, arch, platform, hash, size, storage_key, can_sideload, podfile_lock_hash, created_at FROM release_artifacts WHERE release_id = ?`
	args := []interface{}{releaseID}
	if arch != nil { query += " AND arch = ?"; args = append(args, *arch) }
	if platform != nil { query += " AND platform = ?"; args = append(args, *platform) }
	query += " ORDER BY arch"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil { return nil, err }
	defer rows.Close()
	var result []ArtifactRow
	for rows.Next() {
		var r ArtifactRow
		if err := rows.Scan(&r.ID, &r.ReleaseID, &r.Arch, &r.Platform, &r.Hash, &r.Size, &r.StorageKey, &r.CanSideload, &r.PodfileLockHash, &r.CreatedAt); err != nil { return nil, err }
		result = append(result, r)
	}
	return result, nil
}

// --- Patches ---
func (s *SqliteStore) GetNextPatchNumber(ctx context.Context, releaseID int) (int, error) {
	var num int
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(number), 0) + 1 FROM patches WHERE release_id = ?`, releaseID).Scan(&num)
	return num, err
}
func (s *SqliteStore) CreatePatch(ctx context.Context, releaseID int, number int, notes *string) (*PatchRow, error) {
	r := &PatchRow{ReleaseID: releaseID, Number: number, Notes: notes}
	err := s.db.QueryRowContext(ctx, `INSERT INTO patches (release_id, number, notes) VALUES (?, ?, ?) RETURNING id, created_at`, releaseID, number, notes).Scan(&r.ID, &r.CreatedAt)
	if err != nil { return nil, err }
	return r, nil
}
func (s *SqliteStore) GetPatchByID(ctx context.Context, patchID int) (*PatchRow, error) {
	r := &PatchRow{}
	err := s.db.QueryRowContext(ctx, `SELECT id, release_id, number, notes, created_at FROM patches WHERE id = ?`, patchID).Scan(&r.ID, &r.ReleaseID, &r.Number, &r.Notes, &r.CreatedAt)
	if err != nil { return nil, err }
	return r, nil
}
func (s *SqliteStore) GetLatestPatchForRelease(ctx context.Context, releaseID int) (*PatchRow, error) {
	r := &PatchRow{}
	err := s.db.QueryRowContext(ctx, `SELECT id, release_id, number, notes, created_at FROM patches WHERE release_id = ? ORDER BY number DESC LIMIT 1`, releaseID).Scan(&r.ID, &r.ReleaseID, &r.Number, &r.Notes, &r.CreatedAt)
	if err != nil { return nil, err }
	return r, nil
}
func (s *SqliteStore) GetPatchesByReleaseID(ctx context.Context, releaseID int) ([]PatchWithChannelRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT p.id, p.release_id, p.number, p.notes, p.created_at, COALESCE(pc.channel_id, 0), COALESCE(pc.promoted_at, p.created_at) FROM patches p LEFT JOIN patch_channels pc ON p.id = pc.patch_id WHERE p.release_id = ? ORDER BY p.number DESC`, releaseID)
	if err != nil { return nil, err }
	defer rows.Close()
	var result []PatchWithChannelRow
	for rows.Next() {
		var r PatchWithChannelRow
		if err := rows.Scan(&r.ID, &r.ReleaseID, &r.Number, &r.Notes, &r.CreatedAt, &r.ChannelID, &r.PromotedAt); err != nil { return nil, err }
		result = append(result, r)
	}
	return result, nil
}
func (s *SqliteStore) PromotePatch(ctx context.Context, patchID, channelID int) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO patch_channels (patch_id, channel_id) VALUES (?, ?)`, patchID, channelID)
	return err
}
func (s *SqliteStore) GetLatestPromotedPatch(ctx context.Context, releaseID, channelID int) (*PatchWithArtifactRow, error) {
	r := &PatchWithArtifactRow{}
	err := s.db.QueryRowContext(ctx, `SELECT p.id, p.release_id, p.number, p.notes, p.created_at, pa.hash, pa.storage_key, pa.hash_signature FROM patches p JOIN patch_channels pc ON p.id = pc.patch_id LEFT JOIN patch_artifacts pa ON p.id = pa.patch_id WHERE p.release_id = ? AND pc.channel_id = ? ORDER BY p.number DESC LIMIT 1`, releaseID, channelID).Scan(&r.ID, &r.ReleaseID, &r.Number, &r.Notes, &r.CreatedAt, &r.Hash, &r.StorageKey, &r.HashSignature)
	if err != nil { return nil, err }
	return r, nil
}

// --- Patch Artifacts ---
func (s *SqliteStore) CreatePatchArtifact(ctx context.Context, patchID int, arch, platform, hash, storageKey string, size int64, hashSignature, podfileLockHash *string) (*PatchArtifactRow, error) {
	r := &PatchArtifactRow{PatchID: patchID, Arch: arch, Platform: platform, Hash: hash, Size: size, StorageKey: storageKey, HashSignature: hashSignature, PodfileLockHash: podfileLockHash}
	err := s.db.QueryRowContext(ctx, `INSERT INTO patch_artifacts (patch_id, arch, platform, hash, size, storage_key, hash_signature, podfile_lock_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id, created_at`, patchID, arch, platform, hash, size, storageKey, hashSignature, podfileLockHash).Scan(&r.ID, &r.CreatedAt)
	if err != nil { return nil, err }
	return r, nil
}

// --- Patch Events ---
func (s *SqliteStore) InsertPatchEvent(ctx context.Context, appID uuid.UUID, clientID, arch, platform, releaseVersion, eventType string, patchNumber int, timestamp int64, message *string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO patch_events (app_id, client_id, arch, patch_number, platform, release_version, event_type, timestamp, message) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, appID.String(), clientID, arch, patchNumber, platform, releaseVersion, eventType, timestamp, message)
	return err
}

// --- Rollbacks ---
func (s *SqliteStore) RollbackPatch(ctx context.Context, releaseID, patchNumber int) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO rolled_back_patches (release_id, patch_number) VALUES (?, ?)`, releaseID, patchNumber)
	return err
}
func (s *SqliteStore) GetRolledBackPatchNumbers(ctx context.Context, releaseID int) ([]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT patch_number FROM rolled_back_patches WHERE release_id = ?`, releaseID)
	if err != nil { return nil, err }
	defer rows.Close()
	var result []int
	for rows.Next() { var n int; if err := rows.Scan(&n); err != nil { return nil, err }; result = append(result, n) }
	return result, nil
}

// --- Targeted Devices ---
func (s *SqliteStore) AddPatchTargetDevice(ctx context.Context, patchID int, clientID string) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO patch_target_devices (patch_id, client_id) VALUES (?, ?)`, patchID, clientID)
	return err
}
func (s *SqliteStore) IsPatchTargetedToDevice(ctx context.Context, patchID int, clientID string) (bool, error) {
	var c int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM patch_target_devices WHERE patch_id = ? AND client_id = ?`, patchID, clientID).Scan(&c)
	return c > 0, err
}
func (s *SqliteStore) GetPatchTargetDevices(ctx context.Context, patchID int) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT client_id FROM patch_target_devices WHERE patch_id = ?`, patchID)
	if err != nil { return nil, err }
	defer rows.Close()
	var result []string
	for rows.Next() { var cid string; if err := rows.Scan(&cid); err != nil { return nil, err }; result = append(result, cid) }
	return result, nil
}
func (s *SqliteStore) HasTargetDevices(ctx context.Context, patchID int) (bool, error) {
	var c int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM patch_target_devices WHERE patch_id = ?`, patchID).Scan(&c)
	return c > 0, err
}

// --- Migration ---
func (s *SqliteStore) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS organizations (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, type TEXT NOT NULL DEFAULT 'team', created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
		CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE, name TEXT NOT NULL, password_hash TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
		CREATE TABLE IF NOT EXISTS organization_memberships (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE, role TEXT NOT NULL DEFAULT 'member', created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), UNIQUE(user_id, organization_id));
		CREATE TABLE IF NOT EXISTS apps (id TEXT PRIMARY KEY, organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE, display_name TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
		CREATE TABLE IF NOT EXISTS channels (id INTEGER PRIMARY KEY AUTOINCREMENT, app_id TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE, name TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), UNIQUE(app_id, name));
		CREATE TABLE IF NOT EXISTS releases (id INTEGER PRIMARY KEY AUTOINCREMENT, app_id TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE, version TEXT NOT NULL, flutter_revision TEXT NOT NULL, flutter_version TEXT, display_name TEXT, notes TEXT, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
		CREATE TABLE IF NOT EXISTS release_platform_statuses (id INTEGER PRIMARY KEY AUTOINCREMENT, release_id INTEGER NOT NULL REFERENCES releases(id) ON DELETE CASCADE, platform TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'draft', metadata TEXT DEFAULT '{}', created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), UNIQUE(release_id, platform));
		CREATE TABLE IF NOT EXISTS release_artifacts (id INTEGER PRIMARY KEY AUTOINCREMENT, release_id INTEGER NOT NULL REFERENCES releases(id) ON DELETE CASCADE, arch TEXT NOT NULL, platform TEXT NOT NULL, hash TEXT NOT NULL, size INTEGER NOT NULL DEFAULT 0, storage_key TEXT NOT NULL, can_sideload INTEGER NOT NULL DEFAULT 0, podfile_lock_hash TEXT, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
		CREATE TABLE IF NOT EXISTS patches (id INTEGER PRIMARY KEY AUTOINCREMENT, release_id INTEGER NOT NULL REFERENCES releases(id) ON DELETE CASCADE, number INTEGER NOT NULL, notes TEXT, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), UNIQUE(release_id, number));
		CREATE TABLE IF NOT EXISTS patch_artifacts (id INTEGER PRIMARY KEY AUTOINCREMENT, patch_id INTEGER NOT NULL REFERENCES patches(id) ON DELETE CASCADE, arch TEXT NOT NULL, platform TEXT NOT NULL, hash TEXT NOT NULL, size INTEGER NOT NULL DEFAULT 0, storage_key TEXT NOT NULL, hash_signature TEXT, podfile_lock_hash TEXT, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
		CREATE TABLE IF NOT EXISTS patch_channels (id INTEGER PRIMARY KEY AUTOINCREMENT, patch_id INTEGER NOT NULL REFERENCES patches(id) ON DELETE CASCADE, channel_id INTEGER NOT NULL REFERENCES channels(id) ON DELETE CASCADE, promoted_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), UNIQUE(patch_id, channel_id));
		CREATE TABLE IF NOT EXISTS patch_events (id INTEGER PRIMARY KEY AUTOINCREMENT, app_id TEXT NOT NULL, client_id TEXT NOT NULL, arch TEXT NOT NULL, patch_number INTEGER NOT NULL, platform TEXT NOT NULL, release_version TEXT NOT NULL, event_type TEXT NOT NULL, timestamp INTEGER NOT NULL, message TEXT, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
		CREATE TABLE IF NOT EXISTS rolled_back_patches (id INTEGER PRIMARY KEY AUTOINCREMENT, release_id INTEGER NOT NULL REFERENCES releases(id) ON DELETE CASCADE, patch_number INTEGER NOT NULL, rolled_back_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), UNIQUE(release_id, patch_number));
		CREATE TABLE IF NOT EXISTS patch_target_devices (id INTEGER PRIMARY KEY AUTOINCREMENT, patch_id INTEGER NOT NULL REFERENCES patches(id) ON DELETE CASCADE, client_id TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), UNIQUE(patch_id, client_id));
		CREATE INDEX IF NOT EXISTS idx_releases_app_id ON releases(app_id);
		CREATE INDEX IF NOT EXISTS idx_releases_app_version ON releases(app_id, version);
		CREATE INDEX IF NOT EXISTS idx_patches_release_id ON patches(release_id);
		CREATE INDEX IF NOT EXISTS idx_patch_channels_channel ON patch_channels(channel_id);
		CREATE INDEX IF NOT EXISTS idx_patch_channels_patch ON patch_channels(patch_id);
		CREATE INDEX IF NOT EXISTS idx_patch_events_app ON patch_events(app_id);
		CREATE INDEX IF NOT EXISTS idx_patch_events_client ON patch_events(app_id, client_id);
		CREATE INDEX IF NOT EXISTS idx_rolled_back_release ON rolled_back_patches(release_id);
		CREATE INDEX IF NOT EXISTS idx_patch_target_devices_patch ON patch_target_devices(patch_id);
		CREATE INDEX IF NOT EXISTS idx_patch_target_devices_client ON patch_target_devices(patch_id, client_id);
	`)
	return err
}