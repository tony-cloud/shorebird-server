# Server self-update

A natively installed shorebird-server can find, verify, install and roll back
its own signed releases. The design follows the DaliMaster server's self-updater
(signed release discovery, transactional install with a hash-bound previous
image, supervisor trial with watchdog rollback, quarantine, maintenance upload),
adapted to this server's admin model, configuration and deployment. Differences
are listed at the end.

## Modes

`GET /api/v1/admin/server/update` reports one `mode`:

| Mode | When | Behavior |
| --- | --- | --- |
| `active` | Release build (link-time version **and** pinned signing key), supported platform, not in a container | The process is a supervisor; the server runs as its child. Every operation below is available. |
| `managed_externally` | Docker/Kubernetes/Podman/containerd detected, or `SHOREBIRD_SERVER_MANAGED_EXTERNALLY` set (the Docker image sets `docker`) | Status only, `managed_by` names the manager. Every change answers `409 managed_externally`. Update the image instead. |
| `disabled` | `SERVER_SELF_UPDATE=off` | Status only (`self_update_disabled`). |
| `unavailable` | `unversioned_build` (plain `go build`/`go run`), `trust_unconfigured` (no pinned key), `unsupported_platform`, `executable_unresolved`, `settings_invalid: …`, `updater_config_invalid` | Status only (`self_update_unavailable`). The patch server itself runs normally. |

Only `active` changes how the process runs (supervisor + child). Every other
mode runs the server exactly as before: one process, exit on a startup error.

Supported platforms (asset names): `shorebird-server-linux-amd64`,
`-linux-arm64`, `-darwin-amd64`, `-darwin-arm64`, `-windows-amd64.exe`.

## Installation layout

The executable's directory must be writable by the service account: the new
image is staged there (same filesystem, atomic rename), and the journal
`<executable>.update.json`, the previous image `<executable>.previous-<nanos>`
and `VERSION` live next to it. Recommended Linux layout (see
`deploy/systemd/shorebird-server.service`):

```
/var/lib/shorebird-server/bin/shorebird-server   managed image, owned by the service user
/usr/local/bin/shorebird-server -> /var/lib/shorebird-server/bin/shorebird-server   (root-owned symlink)
/etc/shorebird-server/server.env                 configuration (root:shorebird 0640)
```

The server resolves symlinks before anything else, so it always replaces the
managed image, never the symlink. A root-owned image or a read-only directory
logs `UPDATE_INSTALL_UNAVAILABLE` at start, reports `install_writable: false`
and every install fails with `install_permission_denied`. Install by hand only
into the managed path. Service managers (systemd, launchd, NSSM) start the
normal binary and restart it if it exits; the built-in supervisor handles every
update restart itself. The supervisor keeps running the image it was started
with: after editing `server.env`, restart the service.

## Configuration

Deployment configuration is environment only (`.env.example`):

| Variable | Default | Meaning |
| --- | --- | --- |
| `SERVER_SELF_UPDATE` | `auto` | `off` disables; `on` ignores the container heuristics (for mutable containers such as LXC), not the explicit marker |
| `SHOREBIRD_SERVER_MANAGED_EXTERNALLY` | unset | marks an immutable deployment; the value names the manager |
| `SERVER_UPDATE_STATE_DIR` | executable directory | `server-update.json`, the audit log, the maintenance secret |
| `SERVER_UPDATE_CONFIG_FILE` | `<state dir>/server-update.json` | settings file |
| `SERVER_UPDATE_REPOSITORY` | `tony-cloud/shorebird-server` | GitHub releases to discover |
| `SERVER_UPDATE_GITHUB_TOKEN` | unset | optional API token (rate limits); never sent to the mirror or to asset redirects |
| `SERVER_UPDATE_MIRROR_URL` | `default` = `https://mirrors.tonycloud.cn/` | untrusted GitHub transport mirror; an https URL or `off` |
| `SERVER_UPDATE_TRIAL_SECONDS` | `300` | probation of an updated image (0..3600) |
| `SERVER_UPDATE_STARTUP_TIMEOUT_SECONDS` | `120` | a child must report healthy within this (10..600) |

Administrator settings live in `server-update.json` (0600, written atomically,
unknown fields refused):

```json
{"channel":"stable","use_mirror":false,"auto_update":false,"check_interval_seconds":86400}
```

`check_interval_seconds` is 60..604800 (default one day). Repository, token
and mirror URL are deliberately not editable through the API.

## Administrator API

All routes need a global administrator (`users.is_admin`); organization admins
get `403 admin_required`, anonymous callers `401`. Responses are `no-store`.
Refusals are `{"code","message","details"}`.

| Route | Purpose |
| --- | --- |
| `GET /api/v1/admin/server/update` | status (see below) |
| `PUT /api/v1/admin/server/update` | `{"auto_update","check_interval_seconds","channel"?,"use_mirror"?}`; `400 invalid_config/invalid_interval/invalid_channel` |
| `POST …/check` | discover now, independent of the schedule (`202`; poll GET) |
| `POST …/install` | `{"version"}`: exactly the `available_version` of the last check (`409 check_required` otherwise) |
| `POST …/upload` | raw signed ZIP, `Content-Type: application/zip`, ≤130 MiB. Fully verified before `202` |
| `POST …/rollback` | `{"current_password","current_version","rollback_version"}` (see Manual rollback) |
| `GET …/audit?limit=N` | newest audit events (1..500, default 50) |

Upload rules: a stable-channel ZIP is accepted on either channel, a dev-channel
ZIP needs the `dev` channel (`409 dev_channel_required`), the version must be
newer than the running one (`409 version_not_newer`) and not quarantined
(`409 version_quarantined`). Content refusals are `422`: `invalid_zip`,
`signature_invalid`, `untrusted_signer`, `wrong_platform`, `version_mismatch`,
`checksum_mismatch`, `invalid_release`. During a trial every install is refused
(`409 update_trial_in_progress`). Writes are never retried by the server.

The upload accepts any administrator token, including CLI API keys
(`sb_api_…`), so automation can deliver development builds:

```sh
curl -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/zip' \
  --data-binary @shorebird-server-update-linux-amd64-v0.2.1.zip \
  https://HOST/api/v1/admin/server/update/upload
```

Status fields: `mode`, `managed_by`, `unavailable_reason`, `platform`,
`repository`, the settings, `current_version`, `available_version`, `state`
(`idle`, `checking`, `verifying`, `installing`, `restarting`, `error`),
`error_code`, `last_check`, `next_check`, `journal_state` (`trial`, `healthy`,
`rolled_back`), `rollback_version`, `last_rollback` (`manual`/`watchdog`),
`rolled_back_version`, `development_trust`, `trusted_key_ids`,
`install_writable`. After an install, poll GET across the restart: success is
the new `current_version` with `journal_state` `trial`, then `healthy`; failure
is `state: error`, `error_code: update_rolled_back`, `last_rollback: watchdog`.

## Release discovery

- `stable` reads `GET /repos/<repo>/releases/latest` (never a prerelease);
  `dev` lists the newest 100 releases including prereleases. Only semver tags
  newer than the running version count; downgrades are refused twice (source
  and service).
- A release must carry `<asset>`, `<asset>.manifest.json`, `<asset>.sig` and
  `VERSION`. The manifest and signature are downloaded and verified before any
  other field is trusted; the tag, `VERSION`, the asset size and the signed
  manifest must agree.
- The binary is streamed into a fresh temporary file, size and SHA-256 checked,
  and only then handed to the installer, which checks the hash again. A failed
  origin is retried from scratch on the next target, never appended to.
- Mirror: `use_mirror: true` tries `<mirror><origin URL without scheme>` first,
  then GitHub; otherwise GitHub first, mirror second. Redirects are limited to
  https on `github.com`, `api.github.com`, `*.githubusercontent.com` and the
  mirror host, and never carry the token.
- Automatic updates (`auto_update: true`) check every interval (first check
  right after a healthy start) and install what they find; manual checks never
  install. No check runs while an image is on trial.

## Transaction, trial and rollback

1. The new image is staged next to the executable, its hash re-checked, and
   probed with `--version` (15 s, supervisor variables removed); it must print
   exactly the signed version (`binary_version_mismatch` otherwise).
2. The journal `<executable>.update.json` is written as `prepared` with both
   SHA-256 hashes, the executable is renamed to `.previous-<nanos>`, the staged
   image renamed into place, and the journal set to `trial`. `VERSION` follows.
   An interruption at any point is resolved at the next start by comparing the
   installed hash with the journal.
3. The child exits with status 75; the supervisor starts the new image with
   the expected version. The child acknowledges only after its own `/health`
   answers 200 **and** the database responds, over an authenticated loopback
   heartbeat (every 2 s).
4. Trial: no healthy acknowledgement within the startup timeout (120 s), a
   crash, 60 s without a healthy heartbeat, or a heartbeat with another version
   restores the previous image (only if its hash matches the journal), writes
   `rolled_back` and starts the old version. The failed version is
   **quarantined**: it is never installed again automatically or manually.
   A newer signed version clears this by installing normally.
5. After `SERVER_UPDATE_TRIAL_SECONDS` of continuous health the journal becomes
   `healthy`. From then on a failure is restarted with capped backoff
   (1 s … 60 s), not rolled back; manual rollback stays available.
6. Outside a trial a child in maintenance (below) is kept alive; an updated
   image in maintenance still has to become healthy within the startup timeout.
7. An operator stop (SIGTERM/SIGINT) is forwarded to the child; it shuts down
   gracefully (15 s, then killed) without any rollback.

A binary installed by hand over a finished (`healthy`/`rolled_back`) journal
matches neither hash: the journal is moved to `<journal>.stale-<unix>`
(`update_journal_archived`) and the server starts. An unfinished `trial` with
an unknown image refuses to start (`UPDATE_JOURNAL_INVALID`, see Maintenance).

**Database caveat.** A rollback replaces only the binary. Migrations of the
newer version stay applied; release migrations must remain compatible with the
previous binary (additive only). Take a database backup before installing a
release with data migrations if a rollback must stay possible. Updates never
touch the database themselves.

## Manual rollback

While `rollback_version` is reported (journal `trial` or `healthy`, previous
image present), `POST /api/v1/admin/server/update/rollback` restores it. The
request names the current and the previous version (`409 rollback_conflict`
before any password check), then re-authenticates with the administrator's
**current password**: shorebird-server tokens do not distinguish an interactive
session from an API key, so the password is the step-up for every caller.
Missing password: `403 RECENT_AUTH_REQUIRED`; wrong: `401 REAUTH_FAILED`;
five failures in 15 minutes: `429 REAUTH_RATE_LIMITED`. SSO-only
administrators set a local password through the password reset first. The
server checks that the running image still matches the journal, restores the
previous image and `VERSION`, records `rolled_back` with `manual: true`
(quarantine as above) and restarts. GET then shows `state: idle`,
`last_rollback: manual`. A failed rollback reports `rollback_failed` and is
never retried.

## Maintenance (core cannot start)

A supervised server never crash-loops on a startup error. It stays up on
`SERVER_HOST:SERVER_PORT` and serves only:

| Route | Access |
| --- | --- |
| `GET /health` | public, `503 {"status":"maintenance","code":"SERVER_MAINTENANCE","causes":[…]}` |
| any other route | `503 {"code":"SERVER_MAINTENANCE","causes":[…]}` |
| `GET /api/v1/server/maintenance` | secret: causes (code, stage, action, transient, redacted detail, attempts, next retry) and updater status |
| `POST /api/v1/server/maintenance/retry` | secret: retry the core now |
| `POST /api/v1/server/maintenance/update` | secret: signed ZIP, same rules as the admin upload; the process restarts into it on trial |

The secret is a fresh 256-bit value in `<state dir>/server-maintenance.secret`
(0600), created for the episode and removed once the core is up. It is never
logged or served (`401 MAINTENANCE_SECRET_INVALID` otherwise). The log gets one
line per attempt:
`SERVER MAINTENANCE <CODE> (stage …, attempt n): <action>. Error: <redacted>. <retry>`.

| Code | Retry | Operator action |
| --- | --- | --- |
| `DATABASE_UNAVAILABLE`, `DATABASE_INIT_FAILED`, `STORAGE_UNAVAILABLE`, `LISTEN_FAILED` | automatic, 5 s doubling to 5 min | start/fix the database, object store or port; or upload a fixed build |
| `SIGNING_KEY_INVALID`, `ADMIN_BOOTSTRAP_FAILED`, `ARTIFACT_CONFIG_INVALID` | operator | fix the environment and restart the service |
| `UPDATE_JOURNAL_INVALID`, `UPDATE_ROLLBACK_FAILED` | operator (supervisor maintenance, no upload) | install the intended binary or restore the previous one, move `<executable>.update.json` aside, then retry |
| `UPDATE_JOURNAL_UNWRITABLE`, `UPDATE_RESTART_INVALID` | automatic | make the executable directory writable; see the preceding log lines |

```sh
S=/var/lib/shorebird-server/bin/server-maintenance.secret
curl -sS http://127.0.0.1:8080/health
sudo sh -c "printf 'Authorization: Bearer %s\n' \"\$(cat $S)\"" \
  | curl -sS -H @- http://127.0.0.1:8080/api/v1/server/maintenance
sudo sh -c "printf 'Authorization: Bearer %s\n' \"\$(cat $S)\"" \
  | curl -sS -H @- -H 'Content-Type: application/zip' \
    --data-binary @shorebird-server-update-linux-amd64-v0.2.1.zip http://127.0.0.1:8080/api/v1/server/maintenance/update
```

Unsupervised deployments (Docker, unversioned builds) keep the previous
behavior: the coded line is logged and the process exits 1.

## Docker and other immutable images

The image is immutable, so self-update would be lost on the next container
start and could not be rolled back by the orchestrator. The Dockerfile sets
`SHOREBIRD_SERVER_MANAGED_EXTERNALLY=docker`, and without it the server still
detects `/.dockerenv`, `/run/.containerenv`, `KUBERNETES_SERVICE_HOST` and
container cgroups/mounts. Such a server reports `mode: managed_externally`,
runs no supervisor and never touches its binary; every change returns
`409 managed_externally`. Update by pulling/building a new image
(`docker build --build-arg SERVER_VERSION=v0.2.1 …` makes `--version` and the
status report the version). The image never pins an update signing key.

## Signing key

**Decision: a dedicated Ed25519 key pinned into the binary with `-ldflags`,
not a delegated role of the P4 release root.**

The P4 release root (`docs/HARDENING_CONTRACTS.md` §10 in the workspace) was
considered first. A `server-update` role does not fit it cleanly today:

- `release-delegations.v2` fixes `roles` to exactly `build-manifest` and
  `artifact-catalog` (`additionalProperties: false`), and the device verifier
  (`updater/library/src/release_trust.rs`, `deny_unknown_fields`), flutter_tools
  and `scripts/release_trust.py` parse it strictly. A new role is a contract
  change in three implementations, and every hardened engine already installed
  would reject delegations that contain it (`trust_malformed`), so it cannot be
  added compatibly.
- The delegations document travels inside every hardened app's
  `shorebird.yaml`. Server-only keys do not belong in what devices verify.
- Following the root chain in Go would duplicate the k-of-n chain verifier for
  a single key, and the P4 clock-free device rules do not apply to a server.

The dedicated key keeps the same conventions, so it can move under the root
once the delegations format gains an extension point: PKCS#8 Ed25519 keys, key
IDs `sha256:<hex of the raw public key>`, and a domain-separated message
`open-shorebird.server-update-signature.v1:<hex SHA-256 of the manifest bytes>`
(no P4 signature verifies as an update signature or vice versa).

- **Pin**: `-X github.com/shorebird-server/internal/updater.TrustedKeys=<b64>[,<b64>]`.
  Never read at run time; the environment, settings or a mirror cannot change it.
  A build without it reports `trust_unconfigured`.
- **Rotation**: release N pins old and new keys and is signed with the old;
  N+1 is signed with the new key; a later release drops the old key.
- **Compromise**: publish a release signed with a key that is still pinned,
  pinning only fresh keys. A server that has not yet installed it keeps
  trusting the compromised key, so keep the private key offline or in CI
  secrets only.
- **Development**: `signing/server-update.DEVELOPMENT-ONLY.pem` is public on
  purpose. A binary accepts it only when also linked with
  `updater.DevelopmentTrust=allowed` (`build_update_zip.py --development`);
  such a server logs `SERVER_UPDATE_DEVELOPMENT_TRUST` and reports
  `development_trust: true`. `--production` and `server-update-tool sign
  -production` refuse it. Never deploy a development build.

Create the production key once, offline:

```sh
go run ./cmd/server-update-tool keygen -out server-update-signing.pem   # prints "<base64 public key> <key id>"
```

## Signed artifacts and releases

Per platform: the raw binary `<asset>`, `<asset>.manifest.json`
(`product`, `version`, `channel`, `goos`, `goarch`, `asset`, `sha256`, `size`;
stable versions have no prerelease suffix, dev versions must have one),
`<asset>.sig` (`{"key_id","signature"}`), `VERSION`, and the upload ZIP
`shorebird-server-update-<goos>-<goarch>-<version>.zip` containing exactly
those four files. Unknown, duplicate, nested or oversized entries are refused.

**Local build** (`scripts/build_update_zip.py`, same flags as CI:
`CGO_ENABLED=0 go build -mod=readonly -trimpath -ldflags "-s -w -X …version.Version -X …version.BuildTime -X …updater.TrustedKeys"`):

```sh
# development (public key, local testing only)
python3 scripts/build_update_zip.py --out ../../temp/server-update --development --target linux-amd64
# production
python3 scripts/build_update_zip.py --out DIR --production --key server-update-signing.pem \
  --trusted-keys "$SHOREBIRD_SERVER_UPDATE_PUBLIC_KEYS" --target linux-amd64 --target linux-arm64
```

The version is `--version`, or the next patch after `max(VERSION, v* tags)` as
`vX.Y.Z-dev.<commit UTC time>.g<commit12>` (dev channel). Each ZIP is verified
with `server-update-tool verify-zip` exactly as the server will.

**CI** (`.github/workflows/open-shorebird-ci.yml`, job `server-artifacts`):
every leg runs the script. With the secret `SHOREBIRD_SERVER_UPDATE_SIGNING_KEY`
(PKCS#8 PEM) and the variable `SHOREBIRD_SERVER_UPDATE_PUBLIC_KEYS` it signs
for production, ships the signed binary in the `shorebird-server-<os>-<arch>`
archive and uploads `shorebird-server-update-<os>-<arch>`; without the secret
(forks, PRs) it exercises the pipeline with the DEVELOPMENT-ONLY key and the
archive binary is versioned but unpinned. Publishing happens only on a manual
dispatch with `publish_server_release: true` (optional
`server_release_version`): job `server-release` checks that all five platforms
are production-signed with one version and runs `gh release create` on
`tony-cloud/shorebird-server` with `SHOREBIRD_SERVER_RELEASE_TOKEN`
(prerelease for dev versions, latest for stable ones).

## Auditing

Every settings change, check, install, upload, rollback and maintenance
action, including refusals, appends one JSON line to
`<state dir>/server-update-audit.jsonl` (0600, rotated once at 1 MiB to `.1`)
and to the log (`audit server_update …`): time, action, result code, actor id
and e-mail, `auth` (`token`, `password`, `maintenance_secret`), remote address,
versions and settings. Passwords, tokens, the maintenance secret and signatures
are never recorded. A file (not the database) is used so that maintenance
uploads, which run without a database, are audited in the same place.

## Testing

- `go test ./internal/updater/ ./internal/maintenance/ ./internal/api/handlers/`
  (also with `-race`): signature, key-list and manifest refusals, ZIP layout,
  wrong platform/version/hash/size, discovery and mirror, install refusals and
  permissions, journal recovery and stale journals, quarantine, watchdog
  rollback with real child processes (crash, no acknowledgement, heartbeat
  loss, wrong version, maintenance during trial), probation, restart without
  rollback after probation, manual rollback, container detection, global-admin
  checks, re-authentication and rate limiting, audit content, maintenance
  secret and routes.
- `scripts/e2e_self_update.sh WORK_DIR` builds four development-signed
  versions on this host and drives a real supervisor: v1 → upload v2 → trial →
  healthy → manual rollback (v2 quarantined) → upload a v3 whose `/health`
  fails → watchdog rollback (v3 quarantined) → upload v4 → healthy → operator
  stop with no process left.

## Differences from the DaliMaster reference

| DaliMaster | shorebird-server | Reason |
| --- | --- | --- |
| Always supervised | Supervisor only in `active` mode | Docker and development runs keep their one-process behavior. |
| Container: "keep auto-update disabled" | `managed_externally` detected and enforced | Requested: immutable images must never replace binaries. |
| Updated image rolled back on any later failure | Probation (`SERVER_UPDATE_TRIAL_SECONDS`), then restart without rollback | A database outage a week later should not revert a good binary. |
| Upload requires the dev channel | Stable ZIPs on either channel, dev ZIPs need dev | Air-gapped stable servers can install stable releases. |
| Superuser session vs. personal access token; password + MFA | Global admin; password re-authentication + rate limit for rollback | This server has one token type and no MFA. |
| `trust.UpdatePublicKey` constant, seed file | Pinned key list via `-ldflags`, PKCS#8, key IDs, domain-separated digest | Rotation, P4 conventions, no key in source. |
| `minio/selfupdate` | Two renames under the journal | No new dependency; same transaction. |
| ZIP held in memory | ZIP spooled to a temp file next to the executable | Bounded memory for ~20 MB images. |
| Database audit service | JSONL audit file + log | No audit table here; maintenance has no database. |
| Licence/unactivated surface | none | Not applicable. |

## Operator checklist

1. Generate the production key offline (`server-update-tool keygen`); store
   the PEM as secret `SHOREBIRD_SERVER_UPDATE_SIGNING_KEY` and the public key
   (comma-separated list when rotating) as variable
   `SHOREBIRD_SERVER_UPDATE_PUBLIC_KEYS` in the workspace repository.
2. Create `SHOREBIRD_SERVER_RELEASE_TOKEN` (contents: write on
   `tony-cloud/shorebird-server`) to allow publishing.
3. Dispatch the workflow with `publish_server_release: true` (and a
   `server_release_version` for a stable release).
4. Install the archive binary into the managed path (layout above) with the
   systemd unit; check `GET /api/v1/admin/server/update` shows `mode: active`.
5. Keep Docker deployments on image updates.
