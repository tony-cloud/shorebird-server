# Shorebird Self-Hosted Server

A self-hosted replacement for the Shorebird CodePush API server (`api.shorebird.dev`).

## Quick Start

### Prerequisites
- Go 1.23+
- Docker & Docker Compose (for PostgreSQL and MinIO)

### 1. Start infrastructure

```bash
docker compose up -d
```

### 2. Run database migrations

```bash
make migrate-up
```

Or manually:
```bash
goose -dir internal/db/migrations postgres "postgres://shorebird:shorebird@localhost:5432/shorebird?sslmode=disable" up
```

### 3. Start the server

```bash
make run
```

The server starts on `http://localhost:8080`.

### 4. Open the Web Dashboard

Navigate to **http://localhost:8080** in your browser. You'll see the login page where you can:

- **Register** a new admin account
- **Login** with your credentials

The dashboard provides:

| Page | Features |
|------|----------|
| **Dashboard** | Overview stats (apps, patches, users, orgs), recent apps list |
| **Apps** | Create, list, and delete applications with App ID copy |
| **Users** | View all registered users and their roles |
| **Settings** | Server info, API base URL, and token display (click to copy) |

### 5. Register via API (or use the Web UI)

```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"dev@example.com","password":"securepass","name":"Developer"}'
```

Save the returned `token` for subsequent API calls.

### 6. Configure Shorebird CLI

```bash
export SHOREBIRD_HOSTED_URL=http://localhost:8080
export AUTH_SERVICE_URL=http://localhost:8080/auth
export SHOREBIRD_TOKEN=<your-jwt-token>
```

Then use `shorebird init`, `shorebird release`, and `shorebird patch` as normal.

### 7. Configure device-side `shorebird.yaml`

Add to your Flutter app's `shorebird.yaml`:
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

### API v1 (JWT required unless noted)
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/users/me` | Get current user |
| POST | `/api/v1/users` | Create user |
| GET | `/api/v1/apps` | List apps |
| POST | `/api/v1/apps` | Create app |
| DELETE | `/api/v1/apps/{appId}` | Delete app |
| POST | `/api/v1/apps/{appId}/channels` | Create channel |
| GET | `/api/v1/apps/{appId}/channels` | List channels |
| POST | `/api/v1/apps/{appId}/releases` | Create release |
| GET | `/api/v1/apps/{appId}/releases` | List releases |
| PATCH | `/api/v1/apps/{appId}/releases/{releaseId}` | Update release |
| POST | `/api/v1/apps/{appId}/releases/{releaseId}/artifacts` | Upload release artifact |
| GET | `/api/v1/apps/{appId}/releases/{releaseId}/artifacts` | Get release artifacts |
| POST | `/api/v1/apps/{appId}/patches` | Create patch |
| POST | `/api/v1/apps/{appId}/patches/{patchId}/artifacts` | Upload patch artifact |
| GET | `/api/v1/apps/{appId}/releases/{releaseId}/patches` | List patches |
| POST | `/api/v1/apps/{appId}/patches/promote` | Promote patch to channel |
| GET | `/api/v1/organizations` | List organizations |
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
│  │              PostgreSQL                           │ │
│  │  (apps, releases, patches, artifacts, events)    │ │
│  └──────────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────────┐ │
│  │              MinIO (S3-compatible)                │ │
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
