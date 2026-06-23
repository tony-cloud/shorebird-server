-- +goose Up
-- +goose StatementBegin

-- Organizations table
CREATE TABLE organizations (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'team',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT false,
    is_admin BOOLEAN NOT NULL DEFAULT false,
    must_change_password BOOLEAN NOT NULL DEFAULT false,
    auth_provider TEXT NOT NULL DEFAULT 'password',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Organization memberships
CREATE TABLE organization_memberships (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'member',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, organization_id)
);

-- Server settings
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO settings (key, value) VALUES
    ('registration_enabled', 'true'),
    ('sso_registration_enabled', 'true'),
    ('sso_only_registration', 'false'),
    ('casdoor_endpoint', ''),
    ('casdoor_client_id', ''),
    ('casdoor_client_secret', ''),
    ('casdoor_organization', 'built-in');

-- Email verification and password reset tokens
CREATE TABLE account_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    token_type TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Apps table
CREATE TABLE apps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    display_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Channels table (default "stable" channel created per app)
CREATE TABLE channels (
    id SERIAL PRIMARY KEY,
    app_id UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(app_id, name)
);

-- Releases table
CREATE TABLE releases (
    id SERIAL PRIMARY KEY,
    app_id UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    version TEXT NOT NULL,
    flutter_revision TEXT NOT NULL,
    flutter_version TEXT,
    display_name TEXT,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Release platform statuses
CREATE TABLE release_platform_statuses (
    id SERIAL PRIMARY KEY,
    release_id INTEGER NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
    platform TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(release_id, platform)
);

-- Release artifacts
CREATE TABLE release_artifacts (
    id SERIAL PRIMARY KEY,
    release_id INTEGER NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
    arch TEXT NOT NULL,
    platform TEXT NOT NULL,
    hash TEXT NOT NULL,
    size BIGINT NOT NULL DEFAULT 0,
    storage_key TEXT NOT NULL,
    can_sideload BOOLEAN NOT NULL DEFAULT false,
    podfile_lock_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Patches table
CREATE TABLE patches (
    id SERIAL PRIMARY KEY,
    release_id INTEGER NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
    number INTEGER NOT NULL,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(release_id, number)
);

-- Patch artifacts
CREATE TABLE patch_artifacts (
    id SERIAL PRIMARY KEY,
    patch_id INTEGER NOT NULL REFERENCES patches(id) ON DELETE CASCADE,
    arch TEXT NOT NULL,
    platform TEXT NOT NULL,
    hash TEXT NOT NULL,
    size BIGINT NOT NULL DEFAULT 0,
    storage_key TEXT NOT NULL,
    hash_signature TEXT,
    podfile_lock_hash TEXT,
    offline_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Patch channel promotion (links patches to channels)
CREATE TABLE patch_channels (
    id SERIAL PRIMARY KEY,
    patch_id INTEGER NOT NULL REFERENCES patches(id) ON DELETE CASCADE,
    channel_id INTEGER NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    promoted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(patch_id, channel_id)
);

-- Patch install/event log
CREATE TABLE patch_events (
    id SERIAL PRIMARY KEY,
    app_id UUID NOT NULL,
    client_id TEXT NOT NULL,
    arch TEXT NOT NULL,
    patch_number INTEGER NOT NULL,
    platform TEXT NOT NULL,
    release_version TEXT NOT NULL,
    event_type TEXT NOT NULL,
    timestamp BIGINT NOT NULL,
    message JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Rolled-back patches
CREATE TABLE rolled_back_patches (
    id SERIAL PRIMARY KEY,
    release_id INTEGER NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
    patch_number INTEGER NOT NULL,
    rolled_back_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(release_id, patch_number)
);

-- Targeted device patching (extension beyond standard Shorebird)
CREATE TABLE patch_target_devices (
    id SERIAL PRIMARY KEY,
    patch_id INTEGER NOT NULL REFERENCES patches(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(patch_id, client_id)
);

-- Indexes for common query patterns
CREATE INDEX idx_releases_app_id ON releases(app_id);
CREATE INDEX idx_releases_app_version ON releases(app_id, version);
CREATE INDEX idx_patches_release_id ON patches(release_id);
CREATE INDEX idx_patch_channels_channel ON patch_channels(channel_id);
CREATE INDEX idx_patch_channels_patch ON patch_channels(patch_id);
CREATE INDEX idx_patch_events_app ON patch_events(app_id);
CREATE INDEX idx_patch_events_client ON patch_events(app_id, client_id);
CREATE INDEX idx_rolled_back_release ON rolled_back_patches(release_id);
CREATE INDEX idx_patch_target_devices_patch ON patch_target_devices(patch_id);
CREATE INDEX idx_patch_target_devices_client ON patch_target_devices(patch_id, client_id);
CREATE INDEX idx_account_tokens_token ON account_tokens(token_hash, token_type);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS patch_target_devices CASCADE;
DROP TABLE IF EXISTS rolled_back_patches CASCADE;
DROP TABLE IF EXISTS patch_events CASCADE;
DROP TABLE IF EXISTS patch_channels CASCADE;
DROP TABLE IF EXISTS patch_artifacts CASCADE;
DROP TABLE IF EXISTS patches CASCADE;
DROP TABLE IF EXISTS release_artifacts CASCADE;
DROP TABLE IF EXISTS release_platform_statuses CASCADE;
DROP TABLE IF EXISTS releases CASCADE;
DROP TABLE IF EXISTS channels CASCADE;
DROP TABLE IF EXISTS apps CASCADE;
DROP TABLE IF EXISTS account_tokens CASCADE;
DROP TABLE IF EXISTS settings CASCADE;
DROP TABLE IF EXISTS organization_memberships CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS organizations CASCADE;
-- +goose StatementEnd
