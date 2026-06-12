package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ShorebirdTime wraps time.Time with sql.Scanner support for both
// PostgreSQL (native time.Time) and SQLite (RFC3339Nano TEXT).
type ShorebirdTime struct{ time.Time }

// Scan implements sql.Scanner.
func (st *ShorebirdTime) Scan(v interface{}) error {
	if v == nil {
		st.Time = time.Time{}
		return nil
	}
	switch val := v.(type) {
	case time.Time:
		st.Time = val
		return nil
	case string:
		t, err := time.Parse(time.RFC3339Nano, val)
		if err != nil {
			t, err = time.Parse("2006-01-02 15:04:05", val)
			if err != nil {
				return fmt.Errorf("ShorebirdTime: cannot parse %q", val)
			}
		}
		st.Time = t
		return nil
	case []byte:
		return st.Scan(string(val))
	default:
		return fmt.Errorf("ShorebirdTime: unsupported type %T", v)
	}
}

// Value implements driver.Valuer for SQLite INSERTs.
func (st ShorebirdTime) Value() (interface{}, error) {
	if st.Time.IsZero() {
		return nil, nil
	}
	return st.Time.Format(time.RFC3339Nano), nil
}

// NullShorebirdTime is a nullable variant.
type NullShorebirdTime struct {
	Time  ShorebirdTime
	Valid bool
}

// Scan implements sql.Scanner for nullable time.
func (nst *NullShorebirdTime) Scan(v interface{}) error {
	if v == nil {
		nst.Time = ShorebirdTime{}
		nst.Valid = false
		return nil
	}
	nst.Valid = true
	return nst.Time.Scan(v)
}

// Ensure unused import warnings are suppressed.
var _ sql.Scanner = (*ShorebirdTime)(nil)

// Store is the database abstraction. Both PostgreSQL and SQLite
// backends implement this interface.
type Store interface {
	Close()

	// --- Users ---
	CreateUser(ctx context.Context, email, name, passwordHash string) (int, error)
	GetUserByEmail(ctx context.Context, email string) (*UserRow, error)
	GetUserByID(ctx context.Context, id int) (*UserRow, error)
	ListAllUsers(ctx context.Context) ([]UserListRow, error)

	// --- Organizations ---
	CreateOrganization(ctx context.Context, name, orgType string) (int, error)
	GetOrganizationsByUserID(ctx context.Context, userID int) ([]OrgMembershipRow, error)
	AddUserToOrganization(ctx context.Context, userID, orgID int, role string) error

	// --- Apps ---
	CreateApp(ctx context.Context, orgID int, displayName string) (*AppRow, error)
	GetAppsByOrganization(ctx context.Context, orgID int) ([]AppRow, error)
	GetAppByID(ctx context.Context, appID uuid.UUID) (*AppRow, error)
	GetAppByIDString(ctx context.Context, appID string) (*AppRow, error)
	DeleteApp(ctx context.Context, appID uuid.UUID) error
	GetAppsByUserID(ctx context.Context, userID int) ([]AppRow, error)

	// --- Channels ---
	CreateChannel(ctx context.Context, appID uuid.UUID, name string) (*ChannelRow, error)
	GetChannelsByAppID(ctx context.Context, appID uuid.UUID) ([]ChannelRow, error)
	GetChannelByAppIDAndName(ctx context.Context, appID uuid.UUID, name string) (*ChannelRow, error)

	// --- Releases ---
	CreateRelease(ctx context.Context, appID uuid.UUID, version, flutterRevision string, flutterVersion, displayName *string) (*ReleaseRow, error)
	GetReleaseByID(ctx context.Context, releaseID int) (*ReleaseRow, error)
	GetReleaseByAppIDAndVersion(ctx context.Context, appID uuid.UUID, version string) (*ReleaseRow, error)
	GetReleasesByAppID(ctx context.Context, appID uuid.UUID, sideloadableOnly bool) ([]ReleaseRow, error)
	UpdateReleasePlatformStatus(ctx context.Context, releaseID int, platform, status string, metadata map[string]interface{}) error
	GetReleasePlatformStatuses(ctx context.Context, releaseID int) (map[string]string, error)

	// --- Release Artifacts ---
	CreateReleaseArtifact(ctx context.Context, releaseID int, arch, platform, hash, storageKey string, size int64, canSideload bool, podfileLockHash *string) (*ArtifactRow, error)
	GetReleaseArtifacts(ctx context.Context, releaseID int, arch, platform *string) ([]ArtifactRow, error)

	// --- Patches ---
	GetNextPatchNumber(ctx context.Context, releaseID int) (int, error)
	CreatePatch(ctx context.Context, releaseID int, number int, notes *string) (*PatchRow, error)
	GetPatchByID(ctx context.Context, patchID int) (*PatchRow, error)
	GetLatestPatchForRelease(ctx context.Context, releaseID int) (*PatchRow, error)
	GetPatchesByReleaseID(ctx context.Context, releaseID int) ([]PatchWithChannelRow, error)
	PromotePatch(ctx context.Context, patchID, channelID int) error
	GetLatestPromotedPatch(ctx context.Context, releaseID, channelID int) (*PatchWithArtifactRow, error)

	// --- Patch Artifacts ---
	CreatePatchArtifact(ctx context.Context, patchID int, arch, platform, hash, storageKey string, size int64, hashSignature, podfileLockHash *string) (*PatchArtifactRow, error)

	// --- Patch Events ---
	InsertPatchEvent(ctx context.Context, appID uuid.UUID, clientID, arch, platform, releaseVersion, eventType string, patchNumber int, timestamp int64, message *string) error

	// --- Rollbacks ---
	RollbackPatch(ctx context.Context, releaseID, patchNumber int) error
	GetRolledBackPatchNumbers(ctx context.Context, releaseID int) ([]int, error)

	// --- Targeted Devices ---
	AddPatchTargetDevice(ctx context.Context, patchID int, clientID string) error
	IsPatchTargetedToDevice(ctx context.Context, patchID int, clientID string) (bool, error)
	GetPatchTargetDevices(ctx context.Context, patchID int) ([]string, error)
	HasTargetDevices(ctx context.Context, patchID int) (bool, error)
}

// --- Shared row types (used by both backends) ---

// UserRow represents a user row from the database.
type UserRow struct {
	ID           int
	Email        string
	Name         string
	PasswordHash string
	CreatedAt    ShorebirdTime
}

// OrgMembershipRow represents an organization membership query result.
type OrgMembershipRow struct {
	OrgID   int
	OrgName string
	OrgType string
	Role    string
}

// AppRow represents an app row.
type AppRow struct {
	ID             uuid.UUID
	OrganizationID int
	DisplayName    string
	CreatedAt      ShorebirdTime
	UpdatedAt      ShorebirdTime
}

// ChannelRow represents a channel row.
type ChannelRow struct {
	ID        int
	AppID     uuid.UUID
	Name      string
	CreatedAt ShorebirdTime
}

// ReleaseRow represents a release row.
type ReleaseRow struct {
	ID              int
	AppID           uuid.UUID
	Version         string
	FlutterRevision string
	FlutterVersion  *string
	DisplayName     *string
	Notes           *string
	CreatedAt       ShorebirdTime
	UpdatedAt       ShorebirdTime
}

// ArtifactRow represents a release artifact row.
type ArtifactRow struct {
	ID              int
	ReleaseID       int
	Arch            string
	Platform        string
	Hash            string
	Size            int64
	StorageKey      string
	CanSideload     bool
	PodfileLockHash *string
	CreatedAt       ShorebirdTime
}

// PatchRow represents a patch row.
type PatchRow struct {
	ID        int
	ReleaseID int
	Number    int
	Notes     *string
	CreatedAt ShorebirdTime
}

// PatchWithChannelRow includes channel promotion info.
type PatchWithChannelRow struct {
	ID         int
	ReleaseID  int
	Number     int
	Notes      *string
	CreatedAt  ShorebirdTime
	ChannelID  int
	PromotedAt ShorebirdTime
}

// PatchWithArtifactRow includes artifact info for patch check.
type PatchWithArtifactRow struct {
	ID            int
	ReleaseID     int
	Number        int
	Notes         *string
	CreatedAt     ShorebirdTime
	Hash          string
	StorageKey    string
	HashSignature *string
}

// PatchArtifactRow represents a patch artifact row.
type PatchArtifactRow struct {
	ID              int
	PatchID         int
	Arch            string
	Platform        string
	Hash            string
	Size            int64
	StorageKey      string
	HashSignature   *string
	PodfileLockHash *string
	CreatedAt       ShorebirdTime
}

// UserListRow is used by the admin user listing endpoint.
type UserListRow struct {
	ID        int
	Email     string
	Name      string
	CreatedAt ShorebirdTime
	Role      string
}
