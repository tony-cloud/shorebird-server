package models

import (
	"time"

	"github.com/google/uuid"
)

// App represents a single Shorebird application.
type App struct {
	ID             uuid.UUID `json:"app_id"`
	OrganizationID int       `json:"organization_id,omitempty"`
	DisplayName    string    `json:"display_name"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// AppMetadata is the full app info returned by GET /apps.
type AppMetadata struct {
	AppID                string                    `json:"app_id"`
	OrganizationID       int                       `json:"organization_id,omitempty"`
	DisplayName          string                    `json:"display_name"`
	LatestReleaseVersion *string                   `json:"latest_release_version"`
	LatestPatchNumber    *int                      `json:"latest_patch_number"`
	CreatedAt            time.Time                 `json:"created_at"`
	UpdatedAt            time.Time                 `json:"updated_at"`
	Platforms            []string                  `json:"platforms"`
	LatestReleases       map[string]LatestRelease  `json:"latest_releases"`
	PendingReleases      map[string]PendingRelease `json:"pending_releases"`
	IconURL              *string                   `json:"icon_url"`
}

// LatestRelease represents the latest analyzed release per platform.
type LatestRelease struct {
	ReleaseID    int    `json:"release_id"`
	Version      string `json:"version"`
	ReleaseNotes string `json:"release_notes"`
}

// PendingRelease represents an unanalyzed newer release per platform.
type PendingRelease struct {
	ReleaseID int    `json:"release_id"`
	Version   string `json:"version"`
}

// Channel represents a deployment channel for an app.
type Channel struct {
	ID    int       `json:"id"`
	AppID uuid.UUID `json:"app_id"`
	Name  string    `json:"name"`
}

// ReleasePlatformDetails is the current CLI's per-platform release descriptor.
type ReleasePlatformDetails struct {
	Status      string  `json:"status"`
	SigningMode *string `json:"signing_mode,omitempty"`
}

// Release represents a release of an application.
type Release struct {
	ID               int                               `json:"id"`
	AppID            uuid.UUID                         `json:"app_id"`
	Version          string                            `json:"version"`
	FlutterRevision  string                            `json:"flutter_revision"`
	FlutterVersion   *string                           `json:"flutter_version"`
	DisplayName      *string                           `json:"display_name"`
	Notes            *string                           `json:"notes"`
	PlatformStatuses map[string]string                 `json:"platform_statuses"`
	CreatedAt        time.Time                         `json:"created_at"`
	UpdatedAt        time.Time                         `json:"updated_at"`
	Platforms        map[string]ReleasePlatformDetails `json:"platforms"`
}

// ReleaseStatus values.
const (
	ReleaseStatusDraft    = "draft"
	ReleaseStatusActive   = "active"
	ReleaseStatusInactive = "inactive"
)

// ReleasePlatform values.
const (
	PlatformAndroid = "android"
	PlatformIOS     = "ios"
	PlatformMacOS   = "macos"
	PlatformWindows = "windows"
	PlatformLinux   = "linux"
)

// ArtifactSigning declares the trust anchor embedded in a baseline artifact.
type ArtifactSigning struct {
	Mode         string  `json:"mode"`
	KeyID        *int    `json:"key_id,omitempty"`
	PublicKeyPEM *string `json:"public_key_pem,omitempty"`
}

// ReleaseArtifact represents metadata about a release artifact.
type ReleaseArtifact struct {
	ID              int              `json:"id"`
	ReleaseID       int              `json:"release_id"`
	Arch            string           `json:"arch"`
	Platform        string           `json:"platform"`
	Hash            string           `json:"hash"`
	Size            int64            `json:"size"`
	URL             string           `json:"url"`
	CanSideload     bool             `json:"can_sideload"`
	PodfileLockHash *string          `json:"podfile_lock_hash"`
	CreatedAt       time.Time        `json:"created_at"`
	Signing         *ArtifactSigning `json:"signing,omitempty"`
}

// Patch represents a patch (hotfix update) for a release.
type Patch struct {
	ID     int     `json:"id"`
	Number int     `json:"number"`
	Notes  *string `json:"notes"`
}

// ReleasePatch is the join between releases and patches.
type ReleasePatch struct {
	ID          int       `json:"id"`
	ReleaseID   int       `json:"release_id"`
	PatchID     int       `json:"patch_id"`
	PatchNumber int       `json:"patch_number"`
	CreatedAt   time.Time `json:"created_at"`
}

// PatchArtifact represents metadata about a patch artifact.
type PatchArtifact struct {
	ID        int       `json:"id"`
	PatchID   int       `json:"patch_id"`
	Arch      string    `json:"arch"`
	Platform  string    `json:"platform"`
	Hash      string    `json:"hash"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
}

// PatchCheckRequest is the POST /patches/check request body.
type PatchCheckRequest struct {
	ReleaseVersion       string  `json:"release_version"`
	PatchNumber          *int    `json:"patch_number"`
	PatchHash            *string `json:"patch_hash"`
	Platform             string  `json:"platform"`
	Arch                 string  `json:"arch"`
	AppID                string  `json:"app_id"`
	Channel              string  `json:"channel"`
	ClientID             *string `json:"client_id"`
	CurrentPatchNumber   *int    `json:"current_patch_number"`
	AcceptEncryptedPatch bool    `json:"accept_encrypted_patch,omitempty"`
	Nonce                string  `json:"nonce,omitempty"`
}

// PatchCheckResponse is the POST /patches/check response body.
type PatchCheckResponse struct {
	PatchAvailable         bool                         `json:"patch_available"`
	Patch                  *PatchCheckMetadata          `json:"patch"`
	RolledBackPatchNumbers []int                        `json:"rolled_back_patch_numbers"`
	RemovePatch            *PatchRemoval                `json:"remove_patch,omitempty"`
	Authentication         *PatchResponseAuthentication `json:"authentication,omitempty"`
}

// PatchResponseAuthentication binds delivery and rollback to a request nonce and release context.
type PatchResponseAuthentication struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// PatchCheckMetadata is the patch metadata returned in patch check.
type PatchCheckMetadata struct {
	Number           int                      `json:"number"`
	DownloadURL      string                   `json:"download_url"`
	Hash             string                   `json:"hash"`
	HashSignature    *string                  `json:"hash_signature"`
	OfflineExpiresAt *time.Time               `json:"offline_expires_at,omitempty"`
	Encryption       *PatchEncryptionMetadata `json:"encryption,omitempty"`
}

// PatchEncryptionMetadata describes an encrypted patch download. The patch
// hash above remains the plaintext patch hash; EncryptedHash is the hash of
// the downloaded ciphertext.
type PatchEncryptionMetadata struct {
	Algorithm     string `json:"algorithm"`
	KDF           string `json:"kdf"`
	KeyID         string `json:"key_id"`
	Nonce         string `json:"nonce"`
	AAD           string `json:"aad"`
	AADHash       string `json:"aad_hash"`
	EncryptedHash string `json:"encrypted_hash"`
	DeviceIDHash  string `json:"device_id_hash"`
	CacheKey      string `json:"cache_key"`
}

// PatchRemoval tells open updaters to remove an installed patch at startup.
// Shorebird-compatible clients can use RolledBackPatchNumbers for the same
// removal decision.
type PatchRemoval struct {
	Number           int        `json:"number"`
	Reason           string     `json:"reason"`
	OfflineExpiresAt *time.Time `json:"offline_expires_at,omitempty"`
}

// CreatePatchEventRequest is sent by devices to report patch lifecycle events.
type CreatePatchEventRequest struct {
	Event PatchEvent `json:"event"`
}

// PatchEvent represents a single patch lifecycle event.
type PatchEvent struct {
	AppID          string  `json:"app_id"`
	ClientID       string  `json:"client_id"`
	Arch           string  `json:"arch"`
	PatchNumber    int     `json:"patch_number"`
	Platform       string  `json:"platform"`
	ReleaseVersion string  `json:"release_version"`
	Type           string  `json:"type"`
	Timestamp      int64   `json:"timestamp"`
	Message        *string `json:"message"`
}

// Canonical event identifiers serialized by the native updater.
const (
	EventPatchInstallSuccess = "__patch_install__"
	EventPatchInstallFailure = "__patch_install_failure__"
	EventPatchDownload       = "__patch_download__"
	EventPatchUpdateFailure  = "__patch_update_failure__"
)

// Organization represents an organization.
type Organization struct {
	ID               int       `json:"id"`
	Name             string    `json:"name"`
	OrganizationType string    `json:"organization_type"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// OrganizationMembership represents a user's membership in an org.
type OrganizationMembership struct {
	Organization Organization `json:"organization"`
	Role         string       `json:"role"`
}

// CreateUserRequest is the POST /users request body.
type CreateUserRequest struct {
	Name string `json:"name"`
}

// User represents a Shorebird user.
type User struct {
	ID        int       `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// PrivateUser extends User with private fields.
type PrivateUser struct {
	User
}

// CreateAppRequest is the POST /apps request body.
type CreateAppRequest struct {
	OrganizationID int    `json:"organization_id"`
	DisplayName    string `json:"display_name"`
}

// CreateReleaseRequest is the POST /releases request body.
type CreateReleaseRequest struct {
	Version         string  `json:"version"`
	FlutterRevision string  `json:"flutter_revision"`
	FlutterVersion  *string `json:"flutter_version"`
	DisplayName     *string `json:"display_name"`
}

// CreateReleaseResponse wraps the created release.
type CreateReleaseResponse struct {
	Release Release `json:"release"`
}

// CreateReleaseArtifactRequest is the request for uploading a release artifact.
type CreateReleaseArtifactRequest struct {
	Arch            string  `json:"arch"`
	Platform        string  `json:"platform"`
	Hash            string  `json:"hash"`
	Size            int64   `json:"size"`
	CanSideload     bool    `json:"can_sideload"`
	Filename        string  `json:"filename"`
	PodfileLockHash *string `json:"podfile_lock_hash"`
}

// CreateReleaseArtifactResponse returns the artifact metadata.
type CreateReleaseArtifactResponse struct {
	ID              int       `json:"id"`
	ReleaseID       int       `json:"release_id"`
	Arch            string    `json:"arch"`
	Platform        string    `json:"platform"`
	Hash            string    `json:"hash"`
	Size            int64     `json:"size"`
	URL             string    `json:"url"`
	CreatedAt       time.Time `json:"created_at"`
	CanSideload     bool      `json:"can_sideload"`
	PodfileLockHash *string   `json:"podfile_lock_hash"`
}

// CreatePatchRequest is the POST /patches request body.
type CreatePatchRequest struct {
	ReleaseID int                    `json:"release_id"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// CreatePatchResponse wraps the created patch.
type CreatePatchResponse struct {
	Patch Patch `json:"patch"`
}

// CreatePatchArtifactRequest is the request for uploading a patch artifact.
type CreatePatchArtifactRequest struct {
	Arch             string     `json:"arch"`
	Platform         string     `json:"platform"`
	Hash             string     `json:"hash"`
	Size             int64      `json:"size"`
	HashSignature    *string    `json:"hash_signature"`
	PodfileLockHash  *string    `json:"podfile_lock_hash"`
	OfflineExpiresAt *time.Time `json:"offline_expires_at"`
}

// CreatePatchArtifactResponse returns the patch artifact metadata.
type CreatePatchArtifactResponse struct {
	ID               int        `json:"id"`
	PatchID          int        `json:"patch_id"`
	Arch             string     `json:"arch"`
	Platform         string     `json:"platform"`
	Hash             string     `json:"hash"`
	Size             int64      `json:"size"`
	URL              string     `json:"url"`
	OfflineExpiresAt *time.Time `json:"offline_expires_at,omitempty"`
}

// UpdateReleaseRequest is the PATCH /releases/{id} request body.
type UpdateReleaseRequest struct {
	Status   string                 `json:"status"`
	Platform string                 `json:"platform"`
	Metadata map[string]interface{} `json:"metadata"`
}

// PromotePatchRequest is the POST /patches/promote request body.
type PromotePatchRequest struct {
	PatchID   int `json:"patch_id"`
	ChannelID int `json:"channel_id"`
}

// CreateChannelRequest is the POST /channels request body.
type CreateChannelRequest struct {
	Channel string `json:"channel"`
}

// UpdatePatchRequest is the PATCH /patches request body.
type UpdatePatchRequest struct {
	Notes *string `json:"notes"`
}

// ErrorResponse is returned on errors.
type ErrorResponse struct {
	Message string  `json:"message"`
	Details *string `json:"details"`
}

// AuthTokenRequest is the login request.
type AuthTokenRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// AuthTokenResponse is the login response.
type AuthTokenResponse struct {
	Token              string `json:"token"`
	RefreshToken       string `json:"refresh_token"`
	Email              string `json:"email"`
	MustChangePassword bool   `json:"must_change_password,omitempty"`
}
