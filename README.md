# Shorebird Self-Hosted Server

A self-hosted replacement for the hosted Shorebird CodePush API server.
See `../shorebird/OPEN_SOURCE_REPLACEMENTS.md` for the current audit of public upstream
Shorebird components and the local replacements for hosted Shorebird services.

## Quick Start (Zero Dependencies)

By default the server uses **SQLite** + **local filesystem** - no Docker,
no Postgres, no MinIO needed.

### Prerequisites
- Go 1.26.10 or Go 1.27.3, or a later security-patched supported release.
  Deployment builds must include current Go security fixes; the `go.mod`
  language version does not enforce a secure compiler or standard library.
  The module selects Go 1.26.10 for automatic toolchain builds; any explicit
  `GOTOOLCHAIN` override must still meet these deployment minimums.

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
| `SHOREBIRD_ARTIFACTS_DIR` | *(empty)* | Optional extracted public artifact mirror root containing `shorebird/` |
| `ARTIFACT_PROXY_UPSTREAM` | *(empty)* | Optional HTTP(S) artifact_proxy origin, e.g. `http://127.0.0.1:8082` |
| `SMTP_HOST` | *(empty)* | SMTP host for verification/reset emails; empty logs links |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_FROM` | `shorebird@localhost` | From address for account emails |
| `PATCH_DELIVERY_ENCRYPTION` | `off` | Set to `per_device_aes_gcm` to require encrypted-delivery capability and client identity |
| `PATCH_SIGNING_MASTER_KEY` | *(empty)* | Base64-encoded 32-byte independent key wrapping managed RSA private keys |
| `PATCH_DELIVERY_AES_SECRET` | *(empty)* | Server secret used to derive per-device AES-GCM keys |
| `PATCH_DELIVERY_CACHE_ENCRYPTED` | `true` | Cache per-device encrypted patch artifacts |

JWT credentials are limited to 8 KiB before parsing, including on the legacy
bearer refresh route. This limit excludes the `Bearer ` and optional `sb_api_`
prefixes. Server-issued identity tokens are normally under 1 KiB. Oversized
credentials return HTTP 401; opaque refresh-token rotation is unchanged.

### Serve the CLI's default toolchain URLs

The API defaults to port 8080. Set `SHOREBIRD_ARTIFACTS_DIR` to an extracted
public mirror directory containing `shorebird/` to serve its files under
`/artifacts/shorebird/...`. This route supports read-only GET/HEAD and byte ranges;
it rejects directory listings, symlinks, and writes. Use a dedicated public
mirror directory rather than the server's private database or object storage.

Run the workspace's existing Dart `artifact_proxy` separately on `PORT=8082`
and set `ARTIFACT_PROXY_UPSTREAM=http://127.0.0.1:8082` on the Go API server.
Requests under `/download.flutter.io/...` then forward to the corresponding
path on that proxy, letting the CLI's default API-origin SDK/engine URLs work.
These routes are independently optional; empty settings disable them. Invalid
mirror or proxy configuration prevents startup. The proxy still needs the
matching published custom SDK and engine artifacts for each supported target.

### Multipart uploads with local or S3 storage

Both backends return API-origin multipart POST upload URLs matching the CLI's
existing upload protocol. The S3 adapter streams the file bytes to object
storage with server credentials; it does not return a bare presigned PUT URL.
Set `SERVER_BASE_URL` to the API's externally reachable origin for either backend.

New upload grants bind the storage scope, object key, expiry, and exact declared
file size (positive, at most 2 GiB). Changing a grant is rejected. A stream that
is shorter or longer than its declared size is rejected before a complete
object can be published. Local storage publishes completed uploads atomically.

### Private artifact downloads

Authenticated artifact listings issue 30-minute read URLs through the configured
storage backend. New release and original patch objects use the private release
namespace/bucket. Patch checks issue short-lived presigned URLs, which ordinary
updaters can download without account credentials. Local downloads in either
namespace require a scope/object-bound token; S3 uses presigned GET URLs. Upload
grants cannot authorize downloads. Encrypted delivery caches ciphertext in the
patch namespace, and its download also requires an expiring grant.

Both S3 buckets must deny anonymous access; the bundled MinIO setup enforces
this. For an existing installation that previously stored original patches in
the public patch bucket/namespace, copy each original object (preserving its key)
into the private release bucket/namespace and verify its bytes before retiring
the old public copy and policy. Encrypted cache objects can remain in the patch
bucket. The server does not delete or migrate existing cloud data automatically
and does not fall back to an exposed original if the private object is missing.

### Network diagnostics

The CLI's existing GCP-named diagnostic API uses this server's own origin.
Authenticated requests issue five-minute operation-bound transfer URLs. The
upload endpoint discards exactly one 5,000,000-byte multipart file and returns
204; the download endpoint streams exactly 16,000,000 bytes. Transfer endpoints
require their signed grant, consume bounded data, and do not store probe files.

### Managed patch signing

The CLI's default signing mode requires a separately provisioned wrapping key:

```bash
export PATCH_SIGNING_MASTER_KEY="$(openssl rand -base64 32)"
```

Generate this key once, store it as a deployment secret, and preserve it with the
database backup. It is independent of `JWT_SECRET` and `PATCH_DELIVERY_AES_SECRET`.
An absent key returns HTTP 503 for managed-signing operations; a malformed value
prevents startup. Replacing it does not rotate existing signing keys: existing
wrapped keys become unusable without their original wrapping key. Automatic key
rotation and a rotation API are not implemented.

An organization admin can fetch `/api/v1/apps/{appId}/signing-key`. The server
creates one persistent RSA-2048 key per app and returns only its numeric id and
SubjectPublicKeyInfo public PEM. Private PKCS8 bytes are stored encrypted with
AES-256-GCM, a random nonce, and app-bound authenticated data.

Release artifact registration accepts a multipart `signing` JSON field:
`{"mode":"managed","key_id":123}`, `{"mode":"customer"}`, or
`{"mode":"unsigned"}`. The policy is immutable across a release platform's primary artifacts and
supplements and is returned on artifact listing. Managed patch uploads inherit
the pinned release key and receive a server-generated RSA PKCS1v15 SHA-256
signature over the lowercase UTF-8 final artifact hash string, matching the CLI
and updater. The hash describes the reconstructed installed artifact, rather
than its uploaded diff transport. Customers continue to supply their own
signatures for customer-signed releases. Existing releases with no signing
metadata keep their legacy behavior.

Nonce-aware patch checks for managed releases also return
`authentication:{payload,signature}`. The standard-base64 payload is JSON with
`version:1`, the literal request app/release/platform/architecture/channel/nonce,
patch availability and offer fields, and rollback numbers. Its RSA signature
covers the raw payload bytes. Rollback-only and no-update responses are signed
as well. Clients must verify this against the embedded public key before using
control metadata; requests without a nonce retain the legacy unsigned response.
The updated native updater can require this with
`patch_response_verification: required`. Customer-signed and legacy releases do
not have a server-held key for authenticating these responses.

SQLite adds the signing tables and columns on startup. PostgreSQL deployments
must apply `internal/db/migrations/003_managed_signing.sql` with the existing
Goose migration workflow before using this server version.

### Required encrypted patch delivery

Delivery encryption defaults to `off`. Setting
`PATCH_DELIVERY_ENCRYPTION=per_device_aes_gcm` requires every patch-check request
to include `accept_encrypted_patch:true` and a nonempty `client_id`. Missing
capability or identity returns HTTP 400 with the respective code
`encrypted_patch_capability_required` or `encrypted_patch_client_id_required`;
it never selects a plaintext fallback. Missing server secrets or an unknown
encryption mode fail closed. Capable clients receive an AES-GCM ciphertext URL
and encryption metadata derived from the server secret and app/device/patch
context. Version 2 authenticated data also includes SHA-256 of the actual
compressed/diff transport bytes. Reuploading different transport for the same
final installed hash derives a different AES key, nonce, and cache object.
Cached ciphertext is checked against its deterministic expected bytes before
reuse, and local writes publish atomically. Whole-message encrypted transport is
limited to 128 MiB of plaintext (plus the 16-byte authentication tag); larger
patches require a future chunked authenticated format. Release archive uploads
retain their separate 2 GiB limit.

Clients must provision a compatible app-owned decryption key before advertising
this capability. This server does not provide a key provisioning endpoint; a
generated or overridden device id is not a decryption secret. The nonce-bound
managed response signature includes all encryption metadata, preventing altered
key identifiers, associated data, and ciphertext hashes from being accepted.
Original patch objects remain private as described above.

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
| GET | `/api/v1/apps/{appId}` | Fetch one visible app |
| GET | `/api/v1/apps/{appId}/signing-key` | Get/create managed public key (organization admin) |
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
│  │  shorebird-patches (private ciphertext)                       │ │
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

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at your option (matching Shorebird's licensing).
