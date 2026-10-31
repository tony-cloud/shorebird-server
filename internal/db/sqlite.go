package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
		`INSERT INTO users (email, name, password_hash, is_admin) VALUES (?, ?, ?, NOT EXISTS(SELECT 1 FROM users)) RETURNING id`,
		email, name, passwordHash).Scan(&id)
	return id, err
}
func (s *SqliteStore) EnsureDefaultAdmin(ctx context.Context, email, name, passwordHash string) (bool, error) {
	orgName := name + "'s Org"
	res, err := s.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO users (email, name, password_hash, email_verified, is_admin, must_change_password, auth_provider)
		VALUES (?, ?, ?, 1, 1, 1, 'password')`, email, name, passwordHash)
	if err != nil {
		return false, err
	}
	created, _ := res.RowsAffected()
	var userID int
	if err := s.db.QueryRowContext(ctx, `SELECT id FROM users WHERE email = ?`, email).Scan(&userID); err != nil {
		return created > 0, err
	}
	if created > 0 {
		var orgID int
		if err := s.db.QueryRowContext(ctx, `INSERT INTO organizations (name, type) VALUES (?, 'team') RETURNING id`, orgName).Scan(&orgID); err == nil {
			_ = s.AddUserToOrganization(ctx, userID, orgID, "admin")
		}
	}
	return created > 0, nil
}
func (s *SqliteStore) GetUserByEmail(ctx context.Context, email string) (*UserRow, error) {
	r := &UserRow{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, name, password_hash, email_verified, is_admin, must_change_password, auth_provider, created_at FROM users WHERE email = ?`, email).
		Scan(&r.ID, &r.Email, &r.Name, &r.PasswordHash, &r.EmailVerified, &r.IsAdmin, &r.MustChangePassword, &r.AuthProvider, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return r, nil
}
func (s *SqliteStore) GetUserByID(ctx context.Context, id int) (*UserRow, error) {
	r := &UserRow{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, name, password_hash, email_verified, is_admin, must_change_password, auth_provider, created_at FROM users WHERE id = ?`, id).
		Scan(&r.ID, &r.Email, &r.Name, &r.PasswordHash, &r.EmailVerified, &r.IsAdmin, &r.MustChangePassword, &r.AuthProvider, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return r, nil
}
func (s *SqliteStore) ListAllUsers(ctx context.Context) ([]UserListRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT u.id, u.email, u.name, u.created_at, COALESCE(GROUP_CONCAT(DISTINCT om.role), ''), u.email_verified, u.is_admin, u.must_change_password FROM users u LEFT JOIN organization_memberships om ON u.id = om.user_id GROUP BY u.id ORDER BY u.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []UserListRow
	for rows.Next() {
		var r UserListRow
		if err := rows.Scan(&r.ID, &r.Email, &r.Name, &r.CreatedAt, &r.Role, &r.EmailVerified, &r.IsAdmin, &r.MustChangePassword); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}
func (s *SqliteStore) UpdateUserPassword(ctx context.Context, userID int, passwordHash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?`, passwordHash, userID)
	return err
}
func (s *SqliteStore) ClearMustChangePassword(ctx context.Context, userID int) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET must_change_password = 0 WHERE id = ?`, userID)
	return err
}
func (s *SqliteStore) MarkUserEmailVerified(ctx context.Context, userID int) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET email_verified = 1 WHERE id = ?`, userID)
	return err
}
func (s *SqliteStore) SetUserAdmin(ctx context.Context, userID int, isAdmin bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET is_admin = ? WHERE id = ?`, isAdmin, userID)
	return err
}

// --- Organizations ---
func (s *SqliteStore) CreateOrganization(ctx context.Context, name, orgType string) (int, error) {
	var id int
	err := s.db.QueryRowContext(ctx, `INSERT INTO organizations (name, type) VALUES (?, ?) RETURNING id`, name, orgType).Scan(&id)
	return id, err
}
func (s *SqliteStore) GetOrganizationsByUserID(ctx context.Context, userID int) ([]OrgMembershipRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT o.id, o.name, o.type, om.role, o.created_at FROM organizations o JOIN organization_memberships om ON o.id = om.organization_id WHERE om.user_id = ? ORDER BY o.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []OrgMembershipRow
	for rows.Next() {
		var r OrgMembershipRow
		if err := rows.Scan(&r.OrgID, &r.OrgName, &r.OrgType, &r.Role, &r.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}
func (s *SqliteStore) AddUserToOrganization(ctx context.Context, userID, orgID int, role string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO organization_memberships (user_id, organization_id, role) VALUES (?, ?, ?) ON CONFLICT(user_id, organization_id) DO UPDATE SET role = excluded.role`, userID, orgID, role)
	return err
}
func (s *SqliteStore) ListOrganizationUsers(ctx context.Context, orgID int) ([]OrganizationUserRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT u.id, u.email, u.name, om.role, u.email_verified, u.is_admin, u.must_change_password, u.created_at FROM users u JOIN organization_memberships om ON u.id = om.user_id WHERE om.organization_id = ? ORDER BY u.email`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []OrganizationUserRow
	for rows.Next() {
		var r OrganizationUserRow
		if err := rows.Scan(&r.ID, &r.Email, &r.Name, &r.Role, &r.EmailVerified, &r.IsAdmin, &r.MustChangePassword, &r.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}
func (s *SqliteStore) GetOrganizationRole(ctx context.Context, userID, orgID int) (string, error) {
	var role string
	err := s.db.QueryRowContext(ctx, `SELECT role FROM organization_memberships WHERE user_id = ? AND organization_id = ?`, userID, orgID).Scan(&role)
	return role, err
}

func (s *SqliteStore) GetSetting(ctx context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	return value, err
}
func (s *SqliteStore) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`, key, value, rfcNow())
	return err
}
func (s *SqliteStore) ListSettings(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		result[k] = v
	}
	return result, nil
}
func (s *SqliteStore) CreateAccountToken(ctx context.Context, userID int, tokenHash, tokenType string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO account_tokens (user_id, token_hash, token_type, expires_at) VALUES (?, ?, ?, ?)`, userID, tokenHash, tokenType, ShorebirdTime{Time: expiresAt.UTC()})
	return err
}
func (s *SqliteStore) ConsumeAccountToken(ctx context.Context, tokenHash, tokenType string) (*AccountTokenRow, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	r := &AccountTokenRow{}
	err = tx.QueryRowContext(ctx, `SELECT id, user_id, token_type, expires_at, used_at, created_at FROM account_tokens WHERE token_hash = ? AND token_type = ? AND used_at IS NULL AND expires_at > ?`, tokenHash, tokenType, ShorebirdTime{Time: time.Now().UTC()}).
		Scan(&r.ID, &r.UserID, &r.TokenType, &r.ExpiresAt, &r.UsedAt, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE account_tokens SET used_at = ? WHERE id = ?`, rfcNow(), r.ID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return r, nil
}

// --- Apps ---
// rfcNow returns the current UTC time in RFC3339Nano format for SQLite storage.
func rfcNow() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func (s *SqliteStore) CreateApp(ctx context.Context, orgID int, displayName string) (*AppRow, error) {
	id := uuid.New().String()
	now := rfcNow()
	_, err := s.db.ExecContext(ctx, `INSERT INTO apps (id, organization_id, display_name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`, id, orgID, displayName, now, now)
	if err != nil {
		return nil, err
	}
	uid, _ := uuid.Parse(id)
	t := time.Now().UTC()
	return &AppRow{ID: uid, OrganizationID: orgID, DisplayName: displayName, CreatedAt: ShorebirdTime{Time: t}, UpdatedAt: ShorebirdTime{Time: t}}, nil
}
func (s *SqliteStore) GetAppsByOrganization(ctx context.Context, orgID int) ([]AppRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, organization_id, display_name, created_at, updated_at FROM apps WHERE organization_id = ? ORDER BY display_name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanApps(rows)
}
func (s *SqliteStore) GetAppByID(ctx context.Context, appID uuid.UUID) (*AppRow, error) {
	r := &AppRow{}
	var idStr string
	err := s.db.QueryRowContext(ctx, `SELECT id, organization_id, display_name, created_at, updated_at FROM apps WHERE id = ?`, appID.String()).
		Scan(&idStr, &r.OrganizationID, &r.DisplayName, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	r.ID, _ = uuid.Parse(idStr)
	return r, nil
}
func (s *SqliteStore) GetAppByIDString(ctx context.Context, appID string) (*AppRow, error) {
	id, err := uuid.Parse(appID)
	if err != nil {
		return nil, fmt.Errorf("invalid app_id: %w", err)
	}
	return s.GetAppByID(ctx, id)
}
func (s *SqliteStore) DeleteApp(ctx context.Context, appID uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM apps WHERE id = ?`, appID.String())
	return err
}
func (s *SqliteStore) UpdateAppOrganization(ctx context.Context, appID uuid.UUID, orgID int) error {
	_, err := s.db.ExecContext(ctx, `UPDATE apps SET organization_id = ?, updated_at = ? WHERE id = ?`, orgID, rfcNow(), appID.String())
	return err
}
func (s *SqliteStore) GetAppsByUserID(ctx context.Context, userID int) ([]AppRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT a.id, a.organization_id, a.display_name, a.created_at, a.updated_at FROM apps a JOIN organization_memberships om ON a.organization_id = om.organization_id WHERE om.user_id = ? ORDER BY a.display_name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanApps(rows)
}
func scanApps(rows *sql.Rows) ([]AppRow, error) {
	var result []AppRow
	for rows.Next() {
		var r AppRow
		var idStr string
		if err := rows.Scan(&idStr, &r.OrganizationID, &r.DisplayName, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.ID, _ = uuid.Parse(idStr)
		result = append(result, r)
	}
	return result, nil
}

// --- Channels ---
func (s *SqliteStore) CreateChannel(ctx context.Context, appID uuid.UUID, name string) (*ChannelRow, error) {
	r := &ChannelRow{AppID: appID, Name: name}
	err := s.db.QueryRowContext(ctx, `INSERT INTO channels (app_id, name) VALUES (?, ?) RETURNING id, created_at`, appID.String(), name).Scan(&r.ID, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return r, nil
}
func (s *SqliteStore) GetChannelsByAppID(ctx context.Context, appID uuid.UUID) ([]ChannelRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, app_id, name, created_at FROM channels WHERE app_id = ? ORDER BY name`, appID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []ChannelRow
	for rows.Next() {
		var r ChannelRow
		var aid string
		if err := rows.Scan(&r.ID, &aid, &r.Name, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.AppID, _ = uuid.Parse(aid)
		result = append(result, r)
	}
	return result, nil
}
func (s *SqliteStore) GetChannelByAppIDAndName(ctx context.Context, appID uuid.UUID, name string) (*ChannelRow, error) {
	r := &ChannelRow{}
	var aid string
	err := s.db.QueryRowContext(ctx, `SELECT id, app_id, name, created_at FROM channels WHERE app_id = ? AND name = ?`, appID.String(), name).Scan(&r.ID, &aid, &r.Name, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	r.AppID, _ = uuid.Parse(aid)
	return r, nil
}

// --- Releases ---
func (s *SqliteStore) CreateRelease(ctx context.Context, appID uuid.UUID, version, flutterRevision string, flutterVersion, displayName *string) (*ReleaseRow, error) {
	r := &ReleaseRow{AppID: appID, Version: version, FlutterRevision: flutterRevision, FlutterVersion: flutterVersion, DisplayName: displayName}
	var fv, dn interface{}
	if flutterVersion != nil {
		fv = *flutterVersion
	}
	if displayName != nil {
		dn = *displayName
	}
	err := s.db.QueryRowContext(ctx, `INSERT INTO releases (app_id, version, flutter_revision, flutter_version, display_name) VALUES (?, ?, ?, ?, ?) RETURNING id, notes, created_at, updated_at`, appID.String(), version, flutterRevision, fv, dn).Scan(&r.ID, &r.Notes, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return r, nil
}
func (s *SqliteStore) GetReleaseByID(ctx context.Context, releaseID int) (*ReleaseRow, error) {
	r := &ReleaseRow{}
	var aid string
	err := s.db.QueryRowContext(ctx, `SELECT id, app_id, version, flutter_revision, flutter_version, display_name, notes, created_at, updated_at FROM releases WHERE id = ?`, releaseID).Scan(&r.ID, &aid, &r.Version, &r.FlutterRevision, &r.FlutterVersion, &r.DisplayName, &r.Notes, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	r.AppID, _ = uuid.Parse(aid)
	return r, nil
}
func (s *SqliteStore) GetReleaseByAppIDAndVersion(ctx context.Context, appID uuid.UUID, version string) (*ReleaseRow, error) {
	r := &ReleaseRow{}
	var aid string
	err := s.db.QueryRowContext(ctx, `SELECT id, app_id, version, flutter_revision, flutter_version, display_name, notes, created_at, updated_at FROM releases WHERE app_id = ? AND version = ?`, appID.String(), version).Scan(&r.ID, &aid, &r.Version, &r.FlutterRevision, &r.FlutterVersion, &r.DisplayName, &r.Notes, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	r.AppID, _ = uuid.Parse(aid)
	return r, nil
}
func (s *SqliteStore) GetReleasesByAppID(ctx context.Context, appID uuid.UUID, sideloadableOnly bool) ([]ReleaseRow, error) {
	_ = sideloadableOnly
	rows, err := s.db.QueryContext(ctx, `SELECT id, app_id, version, flutter_revision, flutter_version, display_name, notes, created_at, updated_at FROM releases WHERE app_id = ? ORDER BY created_at DESC`, appID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []ReleaseRow
	for rows.Next() {
		var r ReleaseRow
		var aid string
		if err := rows.Scan(&r.ID, &aid, &r.Version, &r.FlutterRevision, &r.FlutterVersion, &r.DisplayName, &r.Notes, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.AppID, _ = uuid.Parse(aid)
		result = append(result, r)
	}
	return result, nil
}
func (s *SqliteStore) UpdateReleasePlatformStatus(ctx context.Context, releaseID int, platform, status string, metadata map[string]interface{}) error {
	metaJSON := "{}"
	if metadata != nil {
		b, _ := json.Marshal(metadata)
		metaJSON = string(b)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO release_platform_statuses (release_id, platform, status, metadata, updated_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(release_id, platform) DO UPDATE SET status=excluded.status, metadata=excluded.metadata, updated_at=excluded.updated_at`, releaseID, platform, status, metaJSON, rfcNow())
	return err
}
func (s *SqliteStore) GetReleasePlatformStatuses(ctx context.Context, releaseID int) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT platform, status FROM release_platform_statuses WHERE release_id = ?`, releaseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]string)
	for rows.Next() {
		var p, st string
		if err := rows.Scan(&p, &st); err != nil {
			return nil, err
		}
		result[p] = st
	}
	return result, nil
}
func (s *SqliteStore) DeleteRelease(ctx context.Context, releaseID int) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM releases WHERE id = ?`, releaseID)
	return err
}

// --- Release Artifacts ---
func (s *SqliteStore) CreateReleaseArtifact(ctx context.Context, releaseID int, arch, platform, hash, storageKey string, size int64, canSideload bool, podfileLockHash *string, signing ...*ReleaseSigningPolicy) (*ArtifactRow, error) {
	mode, keyID := artifactSigningValues(signing)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var conflicting int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM release_artifacts WHERE release_id = ? AND platform = ? AND (COALESCE(signing_mode, '') <> COALESCE(?, '') OR COALESCE(signing_key_id, 0) <> COALESCE(?, 0))`, releaseID, platform, mode, keyID).Scan(&conflicting); err != nil {
		return nil, err
	}
	if conflicting != 0 {
		return nil, ErrSigningPolicyConflict
	}
	row := &ArtifactRow{ReleaseID: releaseID, Arch: arch, Platform: platform, Hash: hash, Size: size, StorageKey: storageKey, CanSideload: canSideload, PodfileLockHash: podfileLockHash, SigningMode: mode, SigningKeyID: keyID}
	err = tx.QueryRowContext(ctx, `INSERT INTO release_artifacts (release_id, arch, platform, hash, size, storage_key, can_sideload, podfile_lock_hash, signing_mode, signing_key_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id, created_at`, releaseID, arch, platform, hash, size, storageKey, canSideload, podfileLockHash, mode, keyID).Scan(&row.ID, &row.CreatedAt)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return row, nil
}
func (s *SqliteStore) GetReleaseArtifacts(ctx context.Context, releaseID int, arch, platform *string) ([]ArtifactRow, error) {
	query := `SELECT id, release_id, arch, platform, hash, size, storage_key, can_sideload, podfile_lock_hash, created_at, signing_mode, signing_key_id FROM release_artifacts WHERE release_id = ?`
	args := []interface{}{releaseID}
	if arch != nil {
		query += " AND arch = ?"
		args = append(args, *arch)
	}
	if platform != nil {
		query += " AND platform = ?"
		args = append(args, *platform)
	}
	query += " ORDER BY arch"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []ArtifactRow
	for rows.Next() {
		var r ArtifactRow
		if err := rows.Scan(&r.ID, &r.ReleaseID, &r.Arch, &r.Platform, &r.Hash, &r.Size, &r.StorageKey, &r.CanSideload, &r.PodfileLockHash, &r.CreatedAt, &r.SigningMode, &r.SigningKeyID); err != nil {
			return nil, err
		}
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
	if err != nil {
		return nil, err
	}
	return r, nil
}
func (s *SqliteStore) GetPatchByID(ctx context.Context, patchID int) (*PatchRow, error) {
	r := &PatchRow{}
	err := s.db.QueryRowContext(ctx, `SELECT id, release_id, number, notes, created_at FROM patches WHERE id = ?`, patchID).Scan(&r.ID, &r.ReleaseID, &r.Number, &r.Notes, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return r, nil
}
func (s *SqliteStore) GetLatestPatchForRelease(ctx context.Context, releaseID int) (*PatchRow, error) {
	r := &PatchRow{}
	err := s.db.QueryRowContext(ctx, `SELECT id, release_id, number, notes, created_at FROM patches WHERE release_id = ? ORDER BY number DESC LIMIT 1`, releaseID).Scan(&r.ID, &r.ReleaseID, &r.Number, &r.Notes, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return r, nil
}
func (s *SqliteStore) GetPatchesByReleaseID(ctx context.Context, releaseID int) ([]PatchWithChannelRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT p.id, p.release_id, p.number, p.notes, p.created_at, COALESCE(pc.channel_id, 0), COALESCE(pc.promoted_at, p.created_at) FROM patches p LEFT JOIN patch_channels pc ON p.id = pc.patch_id WHERE p.release_id = ? ORDER BY p.number DESC`, releaseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []PatchWithChannelRow
	for rows.Next() {
		var r PatchWithChannelRow
		if err := rows.Scan(&r.ID, &r.ReleaseID, &r.Number, &r.Notes, &r.CreatedAt, &r.ChannelID, &r.PromotedAt); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}
func (s *SqliteStore) PromotePatch(ctx context.Context, patchID, channelID int) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO patch_channels (patch_id, channel_id) VALUES (?, ?)`, patchID, channelID)
	return err
}
func (s *SqliteStore) GetLatestPromotedPatch(ctx context.Context, releaseID, channelID int, arch, platform string) (*PatchWithArtifactRow, error) {
	r := &PatchWithArtifactRow{}
	err := s.db.QueryRowContext(ctx, `SELECT p.id, p.release_id, p.number, p.notes, p.created_at, pa.hash, pa.storage_key, pa.hash_signature, pa.offline_expires_at FROM patches p JOIN patch_channels pc ON p.id = pc.patch_id JOIN patch_artifacts pa ON p.id = pa.patch_id WHERE p.release_id = ? AND pc.channel_id = ? AND pa.arch = ? AND pa.platform = ? AND NOT EXISTS (SELECT 1 FROM rolled_back_patches rb WHERE rb.release_id = p.release_id AND rb.patch_number = p.number) ORDER BY p.number DESC LIMIT 1`, releaseID, channelID, arch, platform).Scan(&r.ID, &r.ReleaseID, &r.Number, &r.Notes, &r.CreatedAt, &r.Hash, &r.StorageKey, &r.HashSignature, &r.OfflineExpiresAt)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (s *SqliteStore) GetPatchByReleaseNumber(ctx context.Context, releaseID, patchNumber int, arch, platform string) (*PatchWithArtifactRow, error) {
	r := &PatchWithArtifactRow{}
	err := s.db.QueryRowContext(ctx, `SELECT p.id, p.release_id, p.number, p.notes, p.created_at, pa.hash, pa.storage_key, pa.hash_signature, pa.offline_expires_at FROM patches p JOIN patch_artifacts pa ON p.id = pa.patch_id WHERE p.release_id = ? AND p.number = ? AND pa.arch = ? AND pa.platform = ? LIMIT 1`, releaseID, patchNumber, arch, platform).Scan(&r.ID, &r.ReleaseID, &r.Number, &r.Notes, &r.CreatedAt, &r.Hash, &r.StorageKey, &r.HashSignature, &r.OfflineExpiresAt)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// --- Patch Artifacts ---
func (s *SqliteStore) CreatePatchArtifact(ctx context.Context, patchID int, arch, platform, hash, storageKey string, size int64, hashSignature, podfileLockHash *string, offlineExpiresAt *time.Time) (*PatchArtifactRow, error) {
	r := &PatchArtifactRow{PatchID: patchID, Arch: arch, Platform: platform, Hash: hash, Size: size, StorageKey: storageKey, HashSignature: hashSignature, PodfileLockHash: podfileLockHash}
	var expires interface{}
	if offlineExpiresAt != nil {
		expires = offlineExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	err := s.db.QueryRowContext(ctx, `INSERT INTO patch_artifacts (patch_id, arch, platform, hash, size, storage_key, hash_signature, podfile_lock_hash, offline_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id, created_at, offline_expires_at`, patchID, arch, platform, hash, size, storageKey, hashSignature, podfileLockHash, expires).Scan(&r.ID, &r.CreatedAt, &r.OfflineExpiresAt)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// --- Patch Events ---
func (s *SqliteStore) InsertPatchEvent(ctx context.Context, appID uuid.UUID, clientID, arch, platform, releaseVersion, eventType string, patchNumber int, timestamp int64, message *string, metadata ...*PatchEventMetadata) error {
	var fields PatchEventMetadata
	if len(metadata) > 0 && metadata[0] != nil {
		fields = *metadata[0]
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO patch_events (app_id, client_id, arch, patch_number, platform, release_version, event_type, timestamp, message, event_id, failure_category) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (app_id, client_id, event_id) WHERE event_id IS NOT NULL DO NOTHING`, appID.String(), clientID, arch, patchNumber, platform, releaseVersion, eventType, timestamp, message, fields.EventID, fields.FailureCategory)
	return err
}
func (s *SqliteStore) ListPatchEvents(ctx context.Context, appID uuid.UUID, beforeID int64, limit int) ([]PatchEventRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, app_id, client_id, arch, patch_number, platform, release_version, event_type, timestamp, message, created_at, event_id, failure_category FROM patch_events WHERE app_id = ? AND (? = 0 OR id < ?) ORDER BY id DESC LIMIT ?`, appID.String(), beforeID, beforeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []PatchEventRow
	for rows.Next() {
		var event PatchEventRow
		if err := rows.Scan(&event.ID, &event.AppID, &event.ClientID, &event.Arch, &event.PatchNumber, &event.Platform, &event.ReleaseVersion, &event.Type, &event.Timestamp, &event.Message, &event.CreatedAt, &event.EventID, &event.FailureCategory); err != nil {
			return nil, err
		}
		result = append(result, event)
	}
	return result, rows.Err()
}

func (s *SqliteStore) ListPatchEventActivity(ctx context.Context, appID uuid.UUID, sinceSeconds, sinceMillis int64) ([]PatchEventActivityRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT client_id, timestamp, platform, release_version, patch_number FROM patch_events WHERE app_id = ? AND client_id <> '' AND ((timestamp < 1000000000000 AND timestamp >= ?) OR (timestamp >= 1000000000000 AND timestamp >= ?))`, appID.String(), sinceSeconds, sinceMillis)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []PatchEventActivityRow
	for rows.Next() {
		var r PatchEventActivityRow
		if err := rows.Scan(&r.ClientID, &r.Timestamp, &r.Platform, &r.ReleaseVersion, &r.PatchNumber); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// --- Rollbacks ---
// SetPatchRolledBack atomically changes rollback state and reports whether it changed.
func (s *SqliteStore) SetPatchRolledBack(ctx context.Context, releaseID, patchNumber int, rolledBack bool) (bool, error) {
	query := `DELETE FROM rolled_back_patches WHERE release_id = ? AND patch_number = ?`
	if rolledBack {
		query = `INSERT OR IGNORE INTO rolled_back_patches (release_id, patch_number) VALUES (?, ?)`
	}
	result, err := s.db.ExecContext(ctx, query, releaseID, patchNumber)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	return affected > 0, err
}

func (s *SqliteStore) RollbackPatch(ctx context.Context, releaseID, patchNumber int) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO rolled_back_patches (release_id, patch_number) VALUES (?, ?)`, releaseID, patchNumber)
	return err
}
func (s *SqliteStore) GetRolledBackPatchNumbers(ctx context.Context, releaseID int) ([]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT patch_number FROM rolled_back_patches WHERE release_id = ?`, releaseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []int
	for rows.Next() {
		var n int
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		result = append(result, n)
	}
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
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var cid string
		if err := rows.Scan(&cid); err != nil {
			return nil, err
		}
		result = append(result, cid)
	}
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
		CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE, name TEXT NOT NULL, password_hash TEXT NOT NULL, email_verified INTEGER NOT NULL DEFAULT 0, is_admin INTEGER NOT NULL DEFAULT 0, must_change_password INTEGER NOT NULL DEFAULT 0, auth_provider TEXT NOT NULL DEFAULT 'password', created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
		CREATE TABLE IF NOT EXISTS organization_memberships (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE, role TEXT NOT NULL DEFAULT 'member', created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), UNIQUE(user_id, organization_id));
		CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
		CREATE TABLE IF NOT EXISTS account_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, token_hash TEXT NOT NULL UNIQUE, token_type TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
		CREATE TABLE IF NOT EXISTS apps (id TEXT PRIMARY KEY, organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE, display_name TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
		CREATE TABLE IF NOT EXISTS managed_signing_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, app_id TEXT NOT NULL UNIQUE REFERENCES apps(id) ON DELETE CASCADE, public_key_pem TEXT NOT NULL, wrapped_private_key TEXT NOT NULL);
		CREATE TABLE IF NOT EXISTS channels (id INTEGER PRIMARY KEY AUTOINCREMENT, app_id TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE, name TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), UNIQUE(app_id, name));
		CREATE TABLE IF NOT EXISTS releases (id INTEGER PRIMARY KEY AUTOINCREMENT, app_id TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE, version TEXT NOT NULL, flutter_revision TEXT NOT NULL, flutter_version TEXT, display_name TEXT, notes TEXT, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
		CREATE TABLE IF NOT EXISTS release_platform_statuses (id INTEGER PRIMARY KEY AUTOINCREMENT, release_id INTEGER NOT NULL REFERENCES releases(id) ON DELETE CASCADE, platform TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'draft', metadata TEXT DEFAULT '{}', created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), UNIQUE(release_id, platform));
		CREATE TABLE IF NOT EXISTS release_artifacts (id INTEGER PRIMARY KEY AUTOINCREMENT, release_id INTEGER NOT NULL REFERENCES releases(id) ON DELETE CASCADE, arch TEXT NOT NULL, platform TEXT NOT NULL, hash TEXT NOT NULL, size INTEGER NOT NULL DEFAULT 0, storage_key TEXT NOT NULL, can_sideload INTEGER NOT NULL DEFAULT 0, podfile_lock_hash TEXT, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
		CREATE TABLE IF NOT EXISTS patches (id INTEGER PRIMARY KEY AUTOINCREMENT, release_id INTEGER NOT NULL REFERENCES releases(id) ON DELETE CASCADE, number INTEGER NOT NULL, notes TEXT, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), UNIQUE(release_id, number));
		CREATE TABLE IF NOT EXISTS patch_artifacts (id INTEGER PRIMARY KEY AUTOINCREMENT, patch_id INTEGER NOT NULL REFERENCES patches(id) ON DELETE CASCADE, arch TEXT NOT NULL, platform TEXT NOT NULL, hash TEXT NOT NULL, size INTEGER NOT NULL DEFAULT 0, storage_key TEXT NOT NULL, hash_signature TEXT, podfile_lock_hash TEXT, offline_expires_at TEXT, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));
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
		CREATE INDEX IF NOT EXISTS idx_account_tokens_token ON account_tokens(token_hash, token_type);
	`)
	if err != nil {
		return err
	}
	alter := []string{
		`ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1`,
		`ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN auth_provider TEXT NOT NULL DEFAULT 'password'`,
		`ALTER TABLE patch_artifacts ADD COLUMN offline_expires_at TEXT`,
		`ALTER TABLE release_artifacts ADD COLUMN signing_mode TEXT`,
		`ALTER TABLE release_artifacts ADD COLUMN signing_key_id INTEGER REFERENCES managed_signing_keys(id)`,
		`ALTER TABLE patch_events ADD COLUMN event_id TEXT`,
		`ALTER TABLE patch_events ADD COLUMN failure_category TEXT`,
	}
	for _, stmt := range alter {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return err
		}
	}
	_, err = s.db.ExecContext(ctx, `
		CREATE UNIQUE INDEX IF NOT EXISTS idx_patch_events_event_id ON patch_events (app_id, client_id, event_id) WHERE event_id IS NOT NULL;
		UPDATE users SET email_verified = 1 WHERE email_verified IS NULL;
		UPDATE users SET is_admin = 1 WHERE id = (SELECT MIN(id) FROM users) AND NOT EXISTS (SELECT 1 FROM users WHERE is_admin = 1);
		INSERT OR IGNORE INTO settings (key, value) VALUES
			('registration_enabled', 'true'),
			('sso_registration_enabled', 'true'),
			('sso_only_registration', 'false'),
			('casdoor_endpoint', ''),
			('casdoor_client_id', ''),
			('casdoor_client_secret', ''),
			('casdoor_organization', 'built-in');
	`)
	return err
}

func (s *SqliteStore) GetPatchArtifacts(ctx context.Context, patchID int) ([]PatchArtifactRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, patch_id, arch, platform, hash, storage_key, size, hash_signature, podfile_lock_hash, offline_expires_at, created_at FROM patch_artifacts WHERE patch_id = ? ORDER BY id`, patchID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []PatchArtifactRow{}
	for rows.Next() {
		var row PatchArtifactRow
		if err := rows.Scan(&row.ID, &row.PatchID, &row.Arch, &row.Platform, &row.Hash, &row.StorageKey, &row.Size, &row.HashSignature, &row.PodfileLockHash, &row.OfflineExpiresAt, &row.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (s *SqliteStore) GetAppSigningKey(ctx context.Context, appID uuid.UUID) (*SigningKeyRow, error) {
	row := &SigningKeyRow{}
	err := s.db.QueryRowContext(ctx, `SELECT id, app_id, public_key_pem, wrapped_private_key FROM managed_signing_keys WHERE app_id = ?`, appID).Scan(&row.ID, &row.AppID, &row.PublicKeyPEM, &row.WrappedPrivateKey)
	return row, err
}
func (s *SqliteStore) GetSigningKeyByID(ctx context.Context, keyID int) (*SigningKeyRow, error) {
	row := &SigningKeyRow{}
	err := s.db.QueryRowContext(ctx, `SELECT id, app_id, public_key_pem, wrapped_private_key FROM managed_signing_keys WHERE id = ?`, keyID).Scan(&row.ID, &row.AppID, &row.PublicKeyPEM, &row.WrappedPrivateKey)
	return row, err
}
func (s *SqliteStore) CreateAppSigningKey(ctx context.Context, appID uuid.UUID, publicKeyPEM, wrappedPrivateKey string) (*SigningKeyRow, error) {
	_, err := s.db.ExecContext(ctx, `INSERT INTO managed_signing_keys (app_id, public_key_pem, wrapped_private_key) VALUES (?, ?, ?) ON CONFLICT(app_id) DO NOTHING`, appID, publicKeyPEM, wrappedPrivateKey)
	if err != nil {
		return nil, err
	}
	return s.GetAppSigningKey(ctx, appID)
}
