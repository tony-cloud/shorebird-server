# Shorebird Self-Hosted Server

A self-hosted replacement for the Shorebird CodePush API server (`api.shorebird.dev`).

## Quick Start (Zero Dependencies)

By default the server uses **SQLite** + **local filesystem** - no Docker,
no Postgres, no MinIO needed.

### Prerequisites
- Go 1.23+

### 1. Build and run

```bash
make run
```

That's it. The server starts on `http://localhost:8080`. SQLite database
and file storage are auto-created under the `data/` directory.

### 2. Open the Web Dashboard

Navigate to **http://localhost:8080** -> Register -> Start managing apps.

### 3. (Optional) Use PostgreSQL + MinIO

For production deployments that need horizontal scaling:

```bash
# Start infrastructure
docker compose --profile full up -d

# Set backend overrides
export DB_DRIVER=postgres
export DATABASE_URL=postgres://shorebird:shorebird@localhost:5432/shorebird?sslmode=disable
export STORAGE_DRIVER=s3
export STORAGE_S3_ENDPOINT=localhost:9000
export STORAGE_S3_ACCESS_KEY=minioadmin
export STORAGE_S3_SECRET_KEY=minioadmin
export STORAGE_S3_USE_SSL=false

# Then run the server
make run
```

### Configuration

All settings via environment variables. See `.env.example` for the full list.

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_DRIVER` | `sqlite` | `sqlite` or `postgres` |
| `DB_PATH` | `data/shorebird.db` | SQLite file path |
| `STORAGE_DRIVER` | `local` | `local` or `s3` |
| `STORAGE_LOCAL_DIR` | `data/storage` | Local storage directory |
| `JWT_SECRET` | *(insecure default)* | Set in production! |
| `SERVER_PORT` | `8080` | HTTP port |
| `SERVER_BASE_URL` | `http://localhost:8080` | Public URL for download links |
| `SMTP_HOST` | *(empty)* | SMTP host for verification/reset emails; empty logs links |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_FROM` | `shorebird@localhost` | From address for account emails |

### Account Security and SSO

New password registrations must verify email before web, CLI, or API access is allowed. Configure SMTP in `.env`; without SMTP, verification and reset links are printed to the server log for development.

On startup, the server ensures a bootstrap admin exists:

- Email: `admin@example.com`
- Password: `admin123`

Override with `DEFAULT_ADMIN_EMAIL`, `DEFAULT_ADMIN_PASSWORD`, and `DEFAULT_ADMIN_NAME`. The bootstrap admin is forced to set a new password on first login.

Admins can manage these settings in the dashboard:

- Casdoor SSO endpoint, app ID, app secret, and organization.
- Password registration enabled/disabled.
- SSO registration enabled/disabled.
- SSO-only registration.
- User email verification and global admin grants.

The first registered account becomes a global admin. Existing SQLite users are marked verified during migration to avoid locking out current installs.

### 6. Configure Shorebird CLI

```bash
export SHOREBIRD_HOSTED_URL=http://localhost:8080
export AUTH_SERVICE_URL=http://localhost:8080/auth
export SHOREBIRD_TOKEN=<your-jwt-token>
```

Then use `shorebird init`, `shorebird release`, and `shorebird patch` as normal.

### 7. Configure device-side `shorebird.yaml`

Add your server URL to the Flutter app's `shorebird.yaml`. The CLI
environment variables make `shorebird release` and `shorebird patch` talk to
your server, but the packaged app also needs `base_url` so the runtime updater
checks the same server.

```yaml
app_id: <your-app-uuid>
base_url: http://your-server.com:8080
```

## API Endpoints

### Auth (public)
| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/register` | Register a new user |
| POST | `/auth/token` | Login (get JWT) |
| POST | `/auth/refresh` | Refresh JWT |
| GET | `/auth/public-settings` | Registration/SSO capabilities for login UI |
| POST | `/auth/verify-email/request` | Send verification email |
| GET | `/auth/verify-email` | Verify email by token |
| POST | `/auth/password-reset/request` | Send password reset email |
| GET | `/auth/password-reset` | Password reset form |
| POST | `/auth/password-reset` | Complete password reset |
| GET | `/auth/sso/login` | Start Casdoor OAuth login |
| GET | `/auth/sso/callback` | Casdoor OAuth callback |

### API v1 (JWT required unless noted)
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/users/me` | Get current user |
| PATCH | `/api/v1/users/me/password` | Change current user's password |
| POST | `/api/v1/users` | Create user |
| GET | `/api/v1/apps` | List apps |
| POST | `/api/v1/apps` | Create app |
| DELETE | `/api/v1/apps/{appId}` | Delete app |
| PATCH | `/api/v1/apps/{appId}/transfer` | Transfer app ownership to another organization |
| POST | `/api/v1/apps/{appId}/channels` | Create channel |
| GET | `/api/v1/apps/{appId}/channels` | List channels |
| POST | `/api/v1/apps/{appId}/releases` | Create release |
| GET | `/api/v1/apps/{appId}/releases` | List releases |
| PATCH | `/api/v1/apps/{appId}/releases/{releaseId}` | Update release |
| DELETE | `/api/v1/apps/{appId}/releases/{releaseId}` | Delete release |
| POST | `/api/v1/apps/{appId}/releases/{releaseId}/artifacts` | Upload release artifact |
| GET | `/api/v1/apps/{appId}/releases/{releaseId}/artifacts` | Get release artifacts |
| POST | `/api/v1/apps/{appId}/patches` | Create patch |
| POST | `/api/v1/apps/{appId}/patches/{patchId}/artifacts` | Upload patch artifact |
| GET | `/api/v1/apps/{appId}/releases/{releaseId}/patches` | List patches |
| POST | `/api/v1/apps/{appId}/patches/promote` | Promote patch to channel |
| GET | `/api/v1/organizations` | List organizations |
| POST | `/api/v1/organizations` | Create organization |
| GET | `/api/v1/organizations/{orgId}/users` | List organization users |
| POST | `/api/v1/organizations/{orgId}/users` | Add/update organization user role |
| **POST** | **`/api/v1/patches/check`** | **Device patch check (public)** |
| **POST** | **`/api/v1/patches/events`** | **Device patch event (public)** |
| GET | `/api/v1/diagnostics/gcp_upload` | Speed test (stub) |
| GET | `/api/v1/diagnostics/gcp_download` | Speed test (stub) |

### Admin: Targeted Device Patching
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/admin/patches/{patchId}/target-devices` | Restrict patch to device(s) |
| GET | `/api/v1/admin/patches/{patchId}/target-devices` | List targeted devices |
| DELETE | `/api/v1/admin/patches/{patchId}/target-devices/{clientId}` | Remove device restriction |

### Admin: Users and Settings
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/admin/users` | List users |
| POST | `/api/v1/admin/users/{userId}/verify-email` | Force verify a user email |
| POST | `/api/v1/admin/users/{userId}/admin` | Grant or revoke global admin |
| GET | `/api/v1/admin/settings` | Get registration and SSO settings |
| PUT | `/api/v1/admin/settings` | Update registration and SSO settings |

## Environment Variables

See `.env.example` for all available configuration options.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                   Developer Machine                   │
│  ┌──────────┐  ┌─────────────┐  ┌─────────────────┐ │
│  │ Shorebird │  │Artifact     │  │ Flutter (forked)│ │
│  │   CLI     │  │Proxy (open) │  │                 │ │
│  └────┬─────┘  └──────┬──────┘  └─────────────────┘ │
│       │               │                               │
└───────┼───────────────┼───────────────────────────────┘
        │               │
        ▼               ▼
┌──────────────────────────────────────────────────────┐
│              Self-Hosted Server (Go)                  │
│  ┌──────────┐  ┌──────────┐  ┌────────────────────┐ │
│  │ Auth API │  │CodePush  │  │  Admin API         │ │
│  │ /auth/*  │  │API /api/*│  │  /api/v1/admin/*   │ │
│  └────┬─────┘  └────┬─────┘  └─────────┬──────────┘ │
│       │             │                  │              │
│       ▼             ▼                  ▼              │
│  ┌──────────────────────────────────────────────────┐ │
│  │              SQLite / PostgreSQL                   │ │
│  │  (apps, releases, patches, artifacts, events)    │ │
│  └──────────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────────┐ │
│  │         Local FS / MinIO (S3-compatible)          │ │
│  │  shorebird-releases (private)                     │ │
│  │  shorebird-patches (public)                       │ │
│  └──────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────┘
        ▲
        │  (patch check + download)
        │
┌───────┴───────────────────────────────────────────────┐
│                   End-User Device                      │
│  ┌──────────────────────────────────────────────────┐ │
│  │  Shorebird Updater (Rust, embedded in app)       │ │
│  │  POST /api/v1/patches/check → download patch     │ │
│  └──────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────┘
```

## License

MIT / Apache 2.0 (matching Shorebird's licensing)
