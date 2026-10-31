package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
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
func (st ShorebirdTime) Value() (driver.Value, error) {
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

// Ptr returns a UTC time pointer when valid, otherwise nil.
func (nst NullShorebirdTime) Ptr() *time.Time {
	if !nst.Valid {
		return nil
	}
	t := nst.Time.Time.UTC()
	return &t
}

// Ensure unused import warnings are suppressed.
var _ sql.Scanner = (*ShorebirdTime)(nil)

// Store is the database abstraction. Both PostgreSQL and SQLite
// backends implement this interface.
type Store interface {
	Close()

	// --- Users ---
	CreateUser(ctx context.Context, email, name, passwordHash string) (int, error)
	EnsureDefaultAdmin(ctx context.Context, email, name, passwordHash string) (bool, error)
	GetUserByEmail(ctx context.Context, email string) (*UserRow, error)
	GetUserByID(ctx context.Context, id int) (*UserRow, error)
	ListAllUsers(ctx context.Context) ([]UserListRow, error)
	UpdateUserPassword(ctx context.Context, userID int, passwordHash string) error
	ClearMustChangePassword(ctx context.Context, userID int) error
	MarkUserEmailVerified(ctx context.Context, userID int) error
	SetUserAdmin(ctx context.Context, userID int, isAdmin bool) error

	// --- Organizations ---
	CreateOrganization(ctx context.Context, name, orgType string) (int, error)
	GetOrganizationsByUserID(ctx context.Context, userID int) ([]OrgMembershipRow, error)
	AddUserToOrganization(ctx context.Context, userID, orgID int, role string) error
	ListOrganizationUsers(ctx context.Context, orgID int) ([]OrganizationUserRow, error)
	GetOrganizationRole(ctx context.Context, userID, orgID int) (string, error)

	// --- Settings and account tokens ---
	GetSetting(ctx context.Context, key string) (string, error)
	SetSetting(ctx context.Context, key, value string) error
	ListSettings(ctx context.Context) (map[string]string, error)
	CreateAccountToken(ctx context.Context, userID int, tokenHash, tokenType string, expiresAt time.Time) error
	ConsumeAccountToken(ctx context.Context, tokenHash, tokenType string) (*AccountTokenRow, error)

	// --- Apps ---
	CreateApp(ctx context.Context, orgID int, displayName string) (*AppRow, error)
	GetAppsByOrganization(ctx context.Context, orgID int) ([]AppRow, error)
	GetAppByID(ctx context.Context, appID uuid.UUID) (*AppRow, error)
	GetAppByIDString(ctx context.Context, appID string) (*AppRow, error)
	DeleteApp(ctx context.Context, appID uuid.UUID) error
	UpdateAppOrganization(ctx context.Context, appID uuid.UUID, orgID int) error
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
	DeleteRelease(ctx context.Context, releaseID int) error

	// --- Managed signing keys ---
	GetAppSigningKey(ctx context.Context, appID uuid.UUID) (*SigningKeyRow, error)
	GetSigningKeyByID(ctx context.Context, keyID int) (*SigningKeyRow, error)
	CreateAppSigningKey(ctx context.Context, appID uuid.UUID, publicKeyPEM, wrappedPrivateKey string) (*SigningKeyRow, error)

	// --- Release Artifacts ---
	CreateReleaseArtifact(ctx context.Context, releaseID int, arch, platform, hash, storageKey string, size int64, canSideload bool, podfileLockHash *string, signing ...*ReleaseSigningPolicy) (*ArtifactRow, error)
	GetReleaseArtifacts(ctx context.Context, releaseID int, arch, platform *string) ([]ArtifactRow, error)

	// --- Patches ---
	GetNextPatchNumber(ctx context.Context, releaseID int) (int, error)
	CreatePatch(ctx context.Context, releaseID int, number int, notes *string) (*PatchRow, error)
	GetPatchByID(ctx context.Context, patchID int) (*PatchRow, error)
	GetLatestPatchForRelease(ctx context.Context, releaseID int) (*PatchRow, error)
	GetPatchesByReleaseID(ctx context.Context, releaseID int) ([]PatchWithChannelRow, error)
	PromotePatch(ctx context.Context, patchID, channelID int) error
	GetLatestPromotedPatch(ctx context.Context, releaseID, channelID int, arch, platform string) (*PatchWithArtifactRow, error)
	GetPatchByReleaseNumber(ctx context.Context, releaseID, patchNumber int, arch, platform string) (*PatchWithArtifactRow, error)

	// --- Patch Artifacts ---
	GetPatchArtifacts(ctx context.Context, patchID int) ([]PatchArtifactRow, error)
	CreatePatchArtifact(ctx context.Context, patchID int, arch, platform, hash, storageKey string, size int64, hashSignature, podfileLockHash *string, offlineExpiresAt *time.Time) (*PatchArtifactRow, error)

	// --- Patch Events ---
	InsertPatchEvent(ctx context.Context, appID uuid.UUID, clientID, arch, platform, releaseVersion, eventType string, patchNumber int, timestamp int64, message *string) error
	ListPatchEvents(ctx context.Context, appID uuid.UUID, beforeID int64, limit int) ([]PatchEventRow, error)
	ListPatchEventActivity(ctx context.Context, appID uuid.UUID, sinceSeconds, sinceMillis int64) ([]PatchEventActivityRow, error)

	// --- Rollbacks ---
	RollbackPatch(ctx context.Context, releaseID, patchNumber int) error
	SetPatchRolledBack(ctx context.Context, releaseID, patchNumber int, rolledBack bool) (bool, error)
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
	ID                 int
	Email              string
	Name               string
	PasswordHash       string
	EmailVerified      bool
	IsAdmin            bool
	MustChangePassword bool
	AuthProvider       string
	CreatedAt          ShorebirdTime
}

// OrgMembershipRow represents an organization membership query result.
type OrgMembershipRow struct {
	OrgID     int
	OrgName   string
	OrgType   string
	Role      string
	CreatedAt ShorebirdTime
}

// OrganizationUserRow is used for organization member listing.
type OrganizationUserRow struct {
	ID                 int
	Email              string
	Name               string
	Role               string
	EmailVerified      bool
	IsAdmin            bool
	MustChangePassword bool
	CreatedAt          ShorebirdTime
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

// ReleaseSigningPolicy is immutable across a release platform's baseline and supplements.
// Nil policy identifies a legacy release without declared signing metadata.
type ReleaseSigningPolicy struct {
	Mode  string
	KeyID *int
}

// SigningKeyRow stores only encrypted private key material alongside its public key.
type SigningKeyRow struct {
	ID                int
	AppID             uuid.UUID
	PublicKeyPEM      string
	WrappedPrivateKey string
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
	SigningMode     *string
	SigningKeyID    *int
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
	ID               int
	ReleaseID        int
	Number           int
	Notes            *string
	CreatedAt        ShorebirdTime
	Hash             string
	StorageKey       string
	HashSignature    *string
	OfflineExpiresAt NullShorebirdTime
}

// PatchArtifactRow represents a patch artifact row.
type PatchArtifactRow struct {
	ID               int
	PatchID          int
	Arch             string
	Platform         string
	Hash             string
	Size             int64
	StorageKey       string
	HashSignature    *string
	PodfileLockHash  *string
	OfflineExpiresAt NullShorebirdTime
	CreatedAt        ShorebirdTime
}

// UserListRow is used by the admin user listing endpoint.
type UserListRow struct {
	ID                 int
	Email              string
	Name               string
	CreatedAt          ShorebirdTime
	Role               string
	EmailVerified      bool
	IsAdmin            bool
	MustChangePassword bool
}

// AccountTokenRow represents a verification or password reset token.
type AccountTokenRow struct {
	ID        int
	UserID    int
	TokenType string
	ExpiresAt ShorebirdTime
	UsedAt    NullShorebirdTime
	CreatedAt ShorebirdTime
}

// PatchEventRow contains a persisted event for the administrative event list.
type PatchEventRow struct {
	ID             int64
	AppID          uuid.UUID
	ClientID       string
	Arch           string
	PatchNumber    int
	Platform       string
	ReleaseVersion string
	Type           string
	Timestamp      int64
	Message        *string
	CreatedAt      ShorebirdTime
}

// PatchEventActivityRow is the minimal activity data needed for metrics.
type PatchEventActivityRow struct {
	ClientID       string
	Timestamp      int64
	Platform       string
	ReleaseVersion string
	PatchNumber    int
}

// ErrSigningPolicyConflict prevents replacing the trust anchor of an existing baseline.
var ErrSigningPolicyConflict = errors.New("release signing policy is immutable")

func artifactSigningValues(signing []*ReleaseSigningPolicy) (*string, *int) {
	if len(signing) == 0 || signing[0] == nil {
		return nil, nil
	}
	return &signing[0].Mode, signing[0].KeyID
}
