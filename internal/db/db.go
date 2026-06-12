package db

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgStore implements Store backed by PostgreSQL.
type PgStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore creates a new PostgreSQL-backed Store.
func NewPostgresStore(ctx context.Context, databaseURL string) (*PgStore, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database URL: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &PgStore{pool: pool}, nil
}

// Close closes the database connection pool.
func (db *PgStore) Close() {
	db.pool.Close()
}

// Exec is a convenience wrapper for pool.Exec.
func (db *PgStore) exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	return db.pool.Exec(ctx, sql, args...)
}

// QueryRow is a convenience wrapper for pool.QueryRow.
func (db *PgStore) queryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	return db.pool.QueryRow(ctx, sql, args...)
}

// Query is a convenience wrapper for pool.Query.
func (db *PgStore) query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	return db.pool.Query(ctx, sql, args...)
}

// --- User queries ---

// CreateUser creates a new user and returns the ID.
func (db *PgStore) CreateUser(ctx context.Context, email, name, passwordHash string) (int, error) {
	var id int
	err := db.queryRow(ctx,
		`INSERT INTO users (email, name, password_hash, is_admin) VALUES ($1, $2, $3, NOT EXISTS(SELECT 1 FROM users)) RETURNING id`,
		email, name, passwordHash,
	).Scan(&id)
	return id, err
}

func (db *PgStore) EnsureDefaultAdmin(ctx context.Context, email, name, passwordHash string) (bool, error) {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var id int
	err = tx.QueryRow(ctx,
		`INSERT INTO users (email, name, password_hash, email_verified, is_admin, must_change_password, auth_provider)
		 VALUES ($1, $2, $3, true, true, true, 'password')
		 ON CONFLICT (email) DO NOTHING
		 RETURNING id`, email, name, passwordHash).Scan(&id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return false, tx.Commit(ctx)
		}
		return false, err
	}
	var orgID int
	if err := tx.QueryRow(ctx, `INSERT INTO organizations (name, type) VALUES ($1, 'team') RETURNING id`, name+"'s Org").Scan(&orgID); err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO organization_memberships (user_id, organization_id, role) VALUES ($1, $2, 'admin')`, id, orgID); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

// GetUserByEmail retrieves a user by email.
func (db *PgStore) GetUserByEmail(ctx context.Context, email string) (*UserRow, error) {
	row := &UserRow{}
	err := db.queryRow(ctx,
		`SELECT id, email, name, password_hash, email_verified, is_admin, must_change_password, auth_provider, created_at FROM users WHERE email = $1`,
		email,
	).Scan(&row.ID, &row.Email, &row.Name, &row.PasswordHash, &row.EmailVerified, &row.IsAdmin, &row.MustChangePassword, &row.AuthProvider, &row.CreatedAt)
	if err != nil {
		return nil, err
	}
	return row, nil
}

// GetUserByID retrieves a user by ID.
func (db *PgStore) GetUserByID(ctx context.Context, id int) (*UserRow, error) {
	row := &UserRow{}
	err := db.queryRow(ctx,
		`SELECT id, email, name, password_hash, email_verified, is_admin, must_change_password, auth_provider, created_at FROM users WHERE id = $1`,
		id,
	).Scan(&row.ID, &row.Email, &row.Name, &row.PasswordHash, &row.EmailVerified, &row.IsAdmin, &row.MustChangePassword, &row.AuthProvider, &row.CreatedAt)
	if err != nil {
		return nil, err
	}
	return row, nil
}

func (db *PgStore) UpdateUserPassword(ctx context.Context, userID int, passwordHash string) error {
	_, err := db.exec(ctx, `UPDATE users SET password_hash = $1, must_change_password = false WHERE id = $2`, passwordHash, userID)
	return err
}

func (db *PgStore) ClearMustChangePassword(ctx context.Context, userID int) error {
	_, err := db.exec(ctx, `UPDATE users SET must_change_password = false WHERE id = $1`, userID)
	return err
}

func (db *PgStore) MarkUserEmailVerified(ctx context.Context, userID int) error {
	_, err := db.exec(ctx, `UPDATE users SET email_verified = true WHERE id = $1`, userID)
	return err
}

func (db *PgStore) SetUserAdmin(ctx context.Context, userID int, isAdmin bool) error {
	_, err := db.exec(ctx, `UPDATE users SET is_admin = $1 WHERE id = $2`, isAdmin, userID)
	return err
}

// --- Organization queries ---

// CreateOrganization creates a new organization.
func (db *PgStore) CreateOrganization(ctx context.Context, name, orgType string) (int, error) {
	var id int
	err := db.queryRow(ctx,
		`INSERT INTO organizations (name, type) VALUES ($1, $2) RETURNING id`,
		name, orgType,
	).Scan(&id)
	return id, err
}

// GetOrganizationsByUserID returns all organizations a user belongs to.
func (db *PgStore) GetOrganizationsByUserID(ctx context.Context, userID int) ([]OrgMembershipRow, error) {
	rows, err := db.query(ctx,
		`SELECT o.id, o.name, o.type, om.role
		 FROM organizations o
		 JOIN organization_memberships om ON o.id = om.organization_id
		 WHERE om.user_id = $1
		 ORDER BY o.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []OrgMembershipRow
	for rows.Next() {
		var r OrgMembershipRow
		if err := rows.Scan(&r.OrgID, &r.OrgName, &r.OrgType, &r.Role); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

// AddUserToOrganization adds a user to an organization.
func (db *PgStore) AddUserToOrganization(ctx context.Context, userID, orgID int, role string) error {
	_, err := db.exec(ctx,
		`INSERT INTO organization_memberships (user_id, organization_id, role)
		 VALUES ($1, $2, $3) ON CONFLICT (user_id, organization_id) DO UPDATE SET role = EXCLUDED.role`,
		userID, orgID, role)
	return err
}

func (db *PgStore) ListOrganizationUsers(ctx context.Context, orgID int) ([]OrganizationUserRow, error) {
	rows, err := db.query(ctx,
		`SELECT u.id, u.email, u.name, om.role, u.email_verified, u.is_admin, u.must_change_password, u.created_at
		 FROM users u
		 JOIN organization_memberships om ON u.id = om.user_id
		 WHERE om.organization_id = $1
		 ORDER BY u.email`, orgID)
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

func (db *PgStore) GetOrganizationRole(ctx context.Context, userID, orgID int) (string, error) {
	var role string
	err := db.queryRow(ctx, `SELECT role FROM organization_memberships WHERE user_id = $1 AND organization_id = $2`, userID, orgID).Scan(&role)
	return role, err
}

// --- App queries ---

// CreateApp creates a new app and returns it.
func (db *PgStore) CreateApp(ctx context.Context, orgID int, displayName string) (*AppRow, error) {
	row := &AppRow{}
	err := db.queryRow(ctx,
		`INSERT INTO apps (organization_id, display_name) VALUES ($1, $2)
		 RETURNING id, organization_id, display_name, created_at, updated_at`,
		orgID, displayName,
	).Scan(&row.ID, &row.OrganizationID, &row.DisplayName, &row.CreatedAt, &row.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return row, nil
}

// GetAppsByOrganization returns all apps for an organization.
func (db *PgStore) GetAppsByOrganization(ctx context.Context, orgID int) ([]AppRow, error) {
	rows, err := db.query(ctx,
		`SELECT id, organization_id, display_name, created_at, updated_at
		 FROM apps WHERE organization_id = $1 ORDER BY display_name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []AppRow
	for rows.Next() {
		var r AppRow
		if err := rows.Scan(&r.ID, &r.OrganizationID, &r.DisplayName, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

// GetAppByID retrieves a single app by ID.
func (db *PgStore) GetAppByID(ctx context.Context, appID uuid.UUID) (*AppRow, error) {
	row := &AppRow{}
	err := db.queryRow(ctx,
		`SELECT id, organization_id, display_name, created_at, updated_at FROM apps WHERE id = $1`,
		appID,
	).Scan(&row.ID, &row.OrganizationID, &row.DisplayName, &row.CreatedAt, &row.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return row, nil
}

// GetAppByIDString retrieves a single app by its string ID.
func (db *PgStore) GetAppByIDString(ctx context.Context, appID string) (*AppRow, error) {
	id, err := uuid.Parse(appID)
	if err != nil {
		return nil, fmt.Errorf("invalid app_id: %w", err)
	}
	return db.GetAppByID(ctx, id)
}

// DeleteApp deletes an app by ID.
func (db *PgStore) DeleteApp(ctx context.Context, appID uuid.UUID) error {
	_, err := db.exec(ctx, `DELETE FROM apps WHERE id = $1`, appID)
	return err
}

func (db *PgStore) UpdateAppOrganization(ctx context.Context, appID uuid.UUID, orgID int) error {
	_, err := db.exec(ctx, `UPDATE apps SET organization_id = $1, updated_at = NOW() WHERE id = $2`, orgID, appID)
	return err
}

// GetAppsByUserID returns all apps the user has access to via org memberships.
func (db *PgStore) GetAppsByUserID(ctx context.Context, userID int) ([]AppRow, error) {
	rows, err := db.query(ctx,
		`SELECT DISTINCT a.id, a.organization_id, a.display_name, a.created_at, a.updated_at
		 FROM apps a
		 JOIN organization_memberships om ON a.organization_id = om.organization_id
		 WHERE om.user_id = $1
		 ORDER BY a.display_name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []AppRow
	for rows.Next() {
		var r AppRow
		if err := rows.Scan(&r.ID, &r.OrganizationID, &r.DisplayName, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

// --- Channel queries ---

// CreateChannel creates a new channel for an app.
func (db *PgStore) CreateChannel(ctx context.Context, appID uuid.UUID, name string) (*ChannelRow, error) {
	row := &ChannelRow{}
	err := db.queryRow(ctx,
		`INSERT INTO channels (app_id, name) VALUES ($1, $2)
		 RETURNING id, app_id, name, created_at`,
		appID, name,
	).Scan(&row.ID, &row.AppID, &row.Name, &row.CreatedAt)
	if err != nil {
		return nil, err
	}
	return row, nil
}

// GetChannelsByAppID returns all channels for an app.
func (db *PgStore) GetChannelsByAppID(ctx context.Context, appID uuid.UUID) ([]ChannelRow, error) {
	rows, err := db.query(ctx,
		`SELECT id, app_id, name, created_at FROM channels WHERE app_id = $1 ORDER BY name`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []ChannelRow
	for rows.Next() {
		var r ChannelRow
		if err := rows.Scan(&r.ID, &r.AppID, &r.Name, &r.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

// GetChannelByAppIDAndName retrieves a specific channel.
func (db *PgStore) GetChannelByAppIDAndName(ctx context.Context, appID uuid.UUID, name string) (*ChannelRow, error) {
	row := &ChannelRow{}
	err := db.queryRow(ctx,
		`SELECT id, app_id, name, created_at FROM channels WHERE app_id = $1 AND name = $2`,
		appID, name,
	).Scan(&row.ID, &row.AppID, &row.Name, &row.CreatedAt)
	if err != nil {
		return nil, err
	}
	return row, nil
}

// --- Release queries ---

// CreateRelease creates a new release.
func (db *PgStore) CreateRelease(ctx context.Context, appID uuid.UUID, version, flutterRevision string, flutterVersion, displayName *string) (*ReleaseRow, error) {
	row := &ReleaseRow{}
	err := db.queryRow(ctx,
		`INSERT INTO releases (app_id, version, flutter_revision, flutter_version, display_name)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, app_id, version, flutter_revision, flutter_version, display_name, notes, created_at, updated_at`,
		appID, version, flutterRevision, flutterVersion, displayName,
	).Scan(&row.ID, &row.AppID, &row.Version, &row.FlutterRevision, &row.FlutterVersion, &row.DisplayName, &row.Notes, &row.CreatedAt, &row.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return row, nil
}

// GetReleaseByID retrieves a release by ID.
func (db *PgStore) GetReleaseByID(ctx context.Context, releaseID int) (*ReleaseRow, error) {
	row := &ReleaseRow{}
	err := db.queryRow(ctx,
		`SELECT id, app_id, version, flutter_revision, flutter_version, display_name, notes, created_at, updated_at
		 FROM releases WHERE id = $1`, releaseID,
	).Scan(&row.ID, &row.AppID, &row.Version, &row.FlutterRevision, &row.FlutterVersion, &row.DisplayName, &row.Notes, &row.CreatedAt, &row.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return row, nil
}

// GetReleaseByAppIDAndVersion retrieves a release by app and version.
func (db *PgStore) GetReleaseByAppIDAndVersion(ctx context.Context, appID uuid.UUID, version string) (*ReleaseRow, error) {
	row := &ReleaseRow{}
	err := db.queryRow(ctx,
		`SELECT id, app_id, version, flutter_revision, flutter_version, display_name, notes, created_at, updated_at
		 FROM releases WHERE app_id = $1 AND version = $2`, appID, version,
	).Scan(&row.ID, &row.AppID, &row.Version, &row.FlutterRevision, &row.FlutterVersion, &row.DisplayName, &row.Notes, &row.CreatedAt, &row.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return row, nil
}

// GetReleasesByAppID returns all releases for an app.
func (db *PgStore) GetReleasesByAppID(ctx context.Context, appID uuid.UUID, sideloadableOnly bool) ([]ReleaseRow, error) {
	query := `SELECT id, app_id, version, flutter_revision, flutter_version, display_name, notes, created_at, updated_at
		 FROM releases WHERE app_id = $1 ORDER BY created_at DESC`
	// Note: sideloadable filtering is done via artifact join if needed
	_ = sideloadableOnly

	rows, err := db.query(ctx, query, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []ReleaseRow
	for rows.Next() {
		var r ReleaseRow
		if err := rows.Scan(&r.ID, &r.AppID, &r.Version, &r.FlutterRevision, &r.FlutterVersion, &r.DisplayName, &r.Notes, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

// UpdateReleasePlatformStatus upserts a platform status for a release.
func (db *PgStore) UpdateReleasePlatformStatus(ctx context.Context, releaseID int, platform, status string, metadata map[string]interface{}) error {
	_, err := db.exec(ctx,
		`INSERT INTO release_platform_statuses (release_id, platform, status, metadata)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (release_id, platform)
		 DO UPDATE SET status = $3, metadata = $4, updated_at = NOW()`,
		releaseID, platform, status, metadata)
	return err
}

// GetReleasePlatformStatuses returns all platform statuses for a release.
func (db *PgStore) GetReleasePlatformStatuses(ctx context.Context, releaseID int) (map[string]string, error) {
	rows, err := db.query(ctx,
		`SELECT platform, status FROM release_platform_statuses WHERE release_id = $1`, releaseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]string)
	for rows.Next() {
		var platform, status string
		if err := rows.Scan(&platform, &status); err != nil {
			return nil, err
		}
		result[platform] = status
	}
	return result, nil
}

func (db *PgStore) DeleteRelease(ctx context.Context, releaseID int) error {
	_, err := db.exec(ctx, `DELETE FROM releases WHERE id = $1`, releaseID)
	return err
}

// --- Release artifact queries ---

// CreateReleaseArtifact creates a release artifact record.
func (db *PgStore) CreateReleaseArtifact(ctx context.Context, releaseID int, arch, platform, hash, storageKey string, size int64, canSideload bool, podfileLockHash *string) (*ArtifactRow, error) {
	row := &ArtifactRow{}
	err := db.queryRow(ctx,
		`INSERT INTO release_artifacts (release_id, arch, platform, hash, size, storage_key, can_sideload, podfile_lock_hash)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING id, release_id, arch, platform, hash, size, storage_key, can_sideload, podfile_lock_hash, created_at`,
		releaseID, arch, platform, hash, size, storageKey, canSideload, podfileLockHash,
	).Scan(&row.ID, &row.ReleaseID, &row.Arch, &row.Platform, &row.Hash, &row.Size, &row.StorageKey, &row.CanSideload, &row.PodfileLockHash, &row.CreatedAt)
	if err != nil {
		return nil, err
	}
	return row, nil
}

// GetReleaseArtifacts returns artifacts for a release, optionally filtered.
func (db *PgStore) GetReleaseArtifacts(ctx context.Context, releaseID int, arch, platform *string) ([]ArtifactRow, error) {
	query := `SELECT id, release_id, arch, platform, hash, size, storage_key, can_sideload, podfile_lock_hash, created_at
		 FROM release_artifacts WHERE release_id = $1`
	args := []interface{}{releaseID}

	if arch != nil {
		query += fmt.Sprintf(" AND arch = $%d", len(args)+1)
		args = append(args, *arch)
	}
	if platform != nil {
		query += fmt.Sprintf(" AND platform = $%d", len(args)+1)
		args = append(args, *platform)
	}

	query += " ORDER BY arch"

	rows, err := db.query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []ArtifactRow
	for rows.Next() {
		var r ArtifactRow
		if err := rows.Scan(&r.ID, &r.ReleaseID, &r.Arch, &r.Platform, &r.Hash, &r.Size, &r.StorageKey, &r.CanSideload, &r.PodfileLockHash, &r.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, nil
}

// --- Patch queries ---

// GetNextPatchNumber returns the next patch number for a release.
func (db *PgStore) GetNextPatchNumber(ctx context.Context, releaseID int) (int, error) {
	var num int
	err := db.queryRow(ctx,
		`SELECT COALESCE(MAX(number), 0) + 1 FROM patches WHERE release_id = $1`, releaseID,
	).Scan(&num)
	return num, err
}

// CreatePatch creates a new patch.
func (db *PgStore) CreatePatch(ctx context.Context, releaseID int, number int, notes *string) (*PatchRow, error) {
	row := &PatchRow{}
	err := db.queryRow(ctx,
		`INSERT INTO patches (release_id, number, notes) VALUES ($1, $2, $3)
		 RETURNING id, release_id, number, notes, created_at`,
		releaseID, number, notes,
	).Scan(&row.ID, &row.ReleaseID, &row.Number, &row.Notes, &row.CreatedAt)
	if err != nil {
		return nil, err
	}
	return row, nil
}

// GetPatchByID retrieves a patch by ID.
func (db *PgStore) GetPatchByID(ctx context.Context, patchID int) (*PatchRow, error) {
	row := &PatchRow{}
	err := db.queryRow(ctx,
		`SELECT id, release_id, number, notes, created_at FROM patches WHERE id = $1`, patchID,
	).Scan(&row.ID, &row.ReleaseID, &row.Number, &row.Notes, &row.CreatedAt)
	if err != nil {
		return nil, err
	}
	return row, nil
}

// GetLatestPatchForRelease returns the latest patch for a release (by number).
func (db *PgStore) GetLatestPatchForRelease(ctx context.Context, releaseID int) (*PatchRow, error) {
	row := &PatchRow{}
	err := db.queryRow(ctx,
		`SELECT id, release_id, number, notes, created_at FROM patches
		 WHERE release_id = $1 ORDER BY number DESC LIMIT 1`, releaseID,
	).Scan(&row.ID, &row.ReleaseID, &row.Number, &row.Notes, &row.CreatedAt)
	if err != nil {
		return nil, err
	}
	return row, nil
}

// GetPatchesByReleaseID returns all patches for a release.
func (db *PgStore) GetPatchesByReleaseID(ctx context.Context, releaseID int) ([]PatchWithChannelRow, error) {
	rows, err := db.query(ctx,
		`SELECT p.id, p.release_id, p.number, p.notes, p.created_at,
		        COALESCE(pc.channel_id, 0) as channel_id, COALESCE(pc.promoted_at, p.created_at) as promoted_at
		 FROM patches p
		 LEFT JOIN patch_channels pc ON p.id = pc.patch_id
		 WHERE p.release_id = $1
		 ORDER BY p.number DESC`, releaseID)
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

// PromotePatch promotes a patch to a channel.
func (db *PgStore) PromotePatch(ctx context.Context, patchID, channelID int) error {
	_, err := db.exec(ctx,
		`INSERT INTO patch_channels (patch_id, channel_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		patchID, channelID)
	return err
}

// GetLatestPromotedPatch returns the latest patch promoted to a specific channel for a release.
func (db *PgStore) GetLatestPromotedPatch(ctx context.Context, releaseID, channelID int) (*PatchWithArtifactRow, error) {
	row := &PatchWithArtifactRow{}
	err := db.queryRow(ctx,
		`SELECT p.id, p.release_id, p.number, p.notes, p.created_at,
		        pa.hash, pa.storage_key, pa.hash_signature
		 FROM patches p
		 JOIN patch_channels pc ON p.id = pc.patch_id
		 LEFT JOIN patch_artifacts pa ON p.id = pa.patch_id
		 WHERE p.release_id = $1 AND pc.channel_id = $2
		 ORDER BY p.number DESC LIMIT 1`,
		releaseID, channelID,
	).Scan(&row.ID, &row.ReleaseID, &row.Number, &row.Notes, &row.CreatedAt,
		&row.Hash, &row.StorageKey, &row.HashSignature)
	if err != nil {
		return nil, err
	}
	return row, nil
}

// --- Patch artifact queries ---

// CreatePatchArtifact creates a patch artifact record.
func (db *PgStore) CreatePatchArtifact(ctx context.Context, patchID int, arch, platform, hash, storageKey string, size int64, hashSignature, podfileLockHash *string) (*PatchArtifactRow, error) {
	row := &PatchArtifactRow{}
	err := db.queryRow(ctx,
		`INSERT INTO patch_artifacts (patch_id, arch, platform, hash, size, storage_key, hash_signature, podfile_lock_hash)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING id, patch_id, arch, platform, hash, size, storage_key, hash_signature, podfile_lock_hash, created_at`,
		patchID, arch, platform, hash, size, storageKey, hashSignature, podfileLockHash,
	).Scan(&row.ID, &row.PatchID, &row.Arch, &row.Platform, &row.Hash, &row.Size, &row.StorageKey, &row.HashSignature, &row.PodfileLockHash, &row.CreatedAt)
	if err != nil {
		return nil, err
	}
	return row, nil
}

// --- Patch events ---

// InsertPatchEvent records a patch lifecycle event.
func (db *PgStore) InsertPatchEvent(ctx context.Context, appID uuid.UUID, clientID, arch, platform, releaseVersion, eventType string, patchNumber int, timestamp int64, message *string) error {
	_, err := db.exec(ctx,
		`INSERT INTO patch_events (app_id, client_id, arch, patch_number, platform, release_version, event_type, timestamp, message)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		appID, clientID, arch, patchNumber, platform, releaseVersion, eventType, timestamp, message)
	return err
}

// --- Rolled back patches ---

// RollbackPatch marks a patch as rolled back.
func (db *PgStore) RollbackPatch(ctx context.Context, releaseID, patchNumber int) error {
	_, err := db.exec(ctx,
		`INSERT INTO rolled_back_patches (release_id, patch_number) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		releaseID, patchNumber)
	return err
}

// GetRolledBackPatchNumbers returns all rolled-back patch numbers for a release.
func (db *PgStore) GetRolledBackPatchNumbers(ctx context.Context, releaseID int) ([]int, error) {
	rows, err := db.query(ctx,
		`SELECT patch_number FROM rolled_back_patches WHERE release_id = $1`, releaseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []int
	for rows.Next() {
		var num int
		if err := rows.Scan(&num); err != nil {
			return nil, err
		}
		result = append(result, num)
	}
	return result, nil
}

// --- Targeted device patching ---

// AddPatchTargetDevice adds a device to a patch's target list.
func (db *PgStore) AddPatchTargetDevice(ctx context.Context, patchID int, clientID string) error {
	_, err := db.exec(ctx,
		`INSERT INTO patch_target_devices (patch_id, client_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		patchID, clientID)
	return err
}

// IsPatchTargetedToDevice checks if a patch is targeted to a specific device.
func (db *PgStore) IsPatchTargetedToDevice(ctx context.Context, patchID int, clientID string) (bool, error) {
	var count int
	err := db.queryRow(ctx,
		`SELECT COUNT(*) FROM patch_target_devices WHERE patch_id = $1 AND client_id = $2`,
		patchID, clientID,
	).Scan(&count)
	return count > 0, err
}

// GetPatchTargetDevices returns all targeted devices for a patch.
func (db *PgStore) GetPatchTargetDevices(ctx context.Context, patchID int) ([]string, error) {
	rows, err := db.query(ctx,
		`SELECT client_id FROM patch_target_devices WHERE patch_id = $1`, patchID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []string
	for rows.Next() {
		var clientID string
		if err := rows.Scan(&clientID); err != nil {
			return nil, err
		}
		result = append(result, clientID)
	}
	return result, nil
}

// HasTargetDevices checks if a patch has any targeted device restrictions.
func (db *PgStore) HasTargetDevices(ctx context.Context, patchID int) (bool, error) {
	var count int
	err := db.queryRow(ctx,
		`SELECT COUNT(*) FROM patch_target_devices WHERE patch_id = $1`, patchID,
	).Scan(&count)
	return count > 0, err
}

// --- Admin queries ---

// ListAllUsers returns all registered users (admin endpoint).
func (db *PgStore) ListAllUsers(ctx context.Context) ([]UserListRow, error) {
	rows, err := db.query(ctx,
		`SELECT u.id, u.email, u.name, u.created_at,
		        COALESCE(string_agg(DISTINCT om.role, ', '), '') as roles
		        , u.email_verified, u.is_admin, u.must_change_password
		 FROM users u
		 LEFT JOIN organization_memberships om ON u.id = om.user_id
		 GROUP BY u.id
		 ORDER BY u.created_at DESC`)
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

func (db *PgStore) GetSetting(ctx context.Context, key string) (string, error) {
	var value string
	err := db.queryRow(ctx, `SELECT value FROM settings WHERE key = $1`, key).Scan(&value)
	return value, err
}

func (db *PgStore) SetSetting(ctx context.Context, key, value string) error {
	_, err := db.exec(ctx,
		`INSERT INTO settings (key, value, updated_at) VALUES ($1, $2, NOW())
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
		key, value)
	return err
}

func (db *PgStore) ListSettings(ctx context.Context) (map[string]string, error) {
	rows, err := db.query(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]string{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		result[key] = value
	}
	return result, nil
}

func (db *PgStore) CreateAccountToken(ctx context.Context, userID int, tokenHash, tokenType string, expiresAt time.Time) error {
	_, err := db.exec(ctx,
		`INSERT INTO account_tokens (user_id, token_hash, token_type, expires_at) VALUES ($1, $2, $3, $4)`,
		userID, tokenHash, tokenType, expiresAt.UTC())
	return err
}

func (db *PgStore) ConsumeAccountToken(ctx context.Context, tokenHash, tokenType string) (*AccountTokenRow, error) {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	row := &AccountTokenRow{}
	err = tx.QueryRow(ctx,
		`SELECT id, user_id, token_type, expires_at, used_at, created_at
		 FROM account_tokens
		 WHERE token_hash = $1 AND token_type = $2 AND used_at IS NULL AND expires_at > NOW()`,
		tokenHash, tokenType).Scan(&row.ID, &row.UserID, &row.TokenType, &row.ExpiresAt, &row.UsedAt, &row.CreatedAt)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE account_tokens SET used_at = NOW() WHERE id = $1`, row.ID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return row, nil
}
