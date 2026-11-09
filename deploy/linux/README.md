# Set up your server (Linux)

`install.sh` installs a self-updating shorebird-server on a Linux host with
systemd (x86_64 or aarch64) in one command: PostgreSQL, the service account,
every runtime secret, the systemd unit, and optionally HTTPS through Caddy. It
needs `python3` (3.8 or later) and the base tools of any distribution; on
Debian/Ubuntu it installs PostgreSQL (and Caddy on request) with apt.

There are two ways to get a trusted server binary. Pick one per host:

| | A. Official release (recommended) | B. Build on the server |
| --- | --- | --- |
| Binary | signed release of `tony-cloud/shorebird-server`, downloaded and verified | built on the host from source at `--ref` |
| Update key | the operator's offline key, pinned in `install.sh` | a host-only key the installer creates in `/etc/shorebird-server` |
| Upgrades | the server's signed self-update (dashboard/API), from GitHub releases | rerun the installer with a newer `--ref` |
| Needs | a published release (once, from the operator's Mac) | ~1 GB disk and 1-3 min CPU per build; GitHub, go.dev and proxy.golang.org reachable |

Both routes end in the same layout and the same self-update transaction (trial,
watchdog rollback, quarantine; `docs/SELF_UPDATE.md`).

## 1. Prepare the VPS (both routes)

1. A Linux x64 (amd64) or arm64 VPS with systemd: Ubuntu 22.04/24.04 or
   Debian 12 are tested. 2 GB RAM is enough (4 GB for route B builds).
2. DNS: create an `A` (and `AAAA` if the VPS has IPv6) record, for example
   `patch.example.com`, pointing at the VPS. Check: `dig +short patch.example.com`.
3. Firewall: open TCP 80 (certificate issuance and redirect) and 443; keep
   8080 closed (the server listens on 127.0.0.1 behind Caddy):

   ```sh
   sudo ufw allow OpenSSH && sudo ufw allow 80,443/tcp && sudo ufw enable   # Ubuntu ufw
   # or the cloud provider's security group: inbound 22, 80, 443 only
   ```

## 2A. Official route

### Once, on the operator's Mac: create the key and publish a release

In shorebird-workspace (needs Go, git and your own `gh auth login`; no token):

```sh
# Dry run: creates the server update key in the private directory if missing,
# pins it in shorebird-server/signing/server-update.trusted-keys and install.sh,
# builds and verifies the signed updates for all 5 platforms. Publishes nothing.
scripts/provision_release_keys.sh server-release --private-dir /Volumes/KEYS/open-shorebird --skip-github

# The first run stops because the new pin files are uncommitted. Commit them
# (only those two files), push, then publish:
scripts/provision_release_keys.sh server-release --private-dir /Volumes/KEYS/open-shorebird --commit-pins --skip-github
git -C shorebird-server push
scripts/provision_release_keys.sh server-release --private-dir /Volumes/KEYS/open-shorebird \
    --version v0.1.0 --publish --skip-github
```

- `--private-dir` must be outside every git checkout, owned by you, mode 0700
  (an encrypted volume or a USB disk; back it up). The key is created once and
  never overwritten; the same directory works with `init`/`rotate`
  (docs/RELEASE_KEYS.md in shorebird-workspace).
- The release is built from a clean worktree of the committed shorebird-server
  `HEAD`; a dirty tree is refused, and `--publish` checks that `HEAD` is on
  GitHub and that the tag does not exist yet.
- `--version vX.Y.Z` publishes a stable release (marked latest); without it the
  next dev version is published as a prerelease.
- Assets: per platform the binary, `.manifest.json`, `.sig`, the update ZIP
  and a `.sha256` for each, plus `VERSION`, `install.sh` and `install.sh.sha256`
  (the layout the installer and the server's self-update discover).
- Replace `--skip-github` by `--apply-github` to also store the key as the CI
  secret `SHOREBIRD_SERVER_UPDATE_SIGNING_KEY` (and the variable
  `SHOREBIRD_SERVER_UPDATE_PUBLIC_KEYS`) of shorebird-workspace, so CI can
  publish later releases (SELF_UPDATE.md, "CI"). Without either flag it shows
  that plan as a dry run.

### On the VPS: one command

```sh
curl -fsSLO https://github.com/tony-cloud/shorebird-server/releases/latest/download/install.sh
curl -fsSLO https://github.com/tony-cloud/shorebird-server/releases/latest/download/install.sh.sha256
sha256sum -c install.sh.sha256
sudo bash install.sh --domain patch.example.com --acme-email you@example.com \
    --admin-email you@example.com --install-caddy
```

`releases/latest` is the newest stable release; for a dev prerelease use
`releases/download/<tag>/install.sh`. The installer verifies the binary's
Ed25519 signature against the key pinned inside it, then its platform,
version, size and SHA-256, then that it prints the signed version.

## 2B. Build-on-server route

On the VPS, no Mac or published release needed:

```sh
curl -fsSL https://raw.githubusercontent.com/tony-cloud/shorebird-server/main/deploy/linux/install.sh -o install.sh
sudo bash install.sh --build-from-source --ref main \
    --domain patch.example.com --acme-email you@example.com --admin-email you@example.com --install-caddy
```

1. Resolves `--ref` (branch, tag or commit) to a commit with the GitHub API and
   downloads that commit's source archive (`--source-dir DIR` builds a local
   git checkout instead).
2. Downloads the Go toolchain named by `go.mod` (`toolchain goX.Y.Z`) from
   go.dev and checks its SHA-256 against go.dev's published list. It is kept in
   `/var/lib/shorebird-server-installer/toolchains` (root, 0700) with the Go
   module and build caches, never installed system-wide. Modules are verified
   by Go against `go.sum` and the checksum database.
3. Creates `/etc/shorebird-server/server-update-signing.pem` (Ed25519 PKCS#8,
   root:root 0600) once and its public `server-update.trusted-keys`; neither is
   ever overwritten.
4. Builds with the release flags (`CGO_ENABLED=0`, `-trimpath`, version, build
   time, `TrustedKeys` = the host key), signs the manifest with the host key in
   production mode, zips it, and installs it through the same verification as
   route A, checked against the host key.

A tag `vX.Y.Z` builds that stable version; any other ref builds
`vX.Y.(Z+1)-dev.<commit time>.g<commit>`, which sorts after the installed
version for every later commit.

**Auto-update is effectively off** in this mode: the binary trusts only the
host key, so GitHub releases (signed by the release key) are refused as
`untrusted_signer` and a manual check reports that. Upgrade by rerunning the
installer. A host installed by route A cannot switch to route B (its binary
does not trust the host key) and the installer refuses to try.

## 3. What the installer does (both routes)

- **Database** (decided on the first install, kept on reruns):
  - default: the local PostgreSQL. If none exists (any version, packaged or
    not, running or stopped, or a socket at `--pg-socket`/`--pg-port`) it runs
    `apt-get install postgresql`; client tools alone are added when only they
    are missing. It creates the restricted login role `shorebird` and the
    database `shorebird` owned by it, prepends one peer rule
    `local shorebird shorebird peer` to `pg_hba.conf` (backup first; validated
    with `pg_hba_file_rules`, reloaded, and restored if the service account
    cannot then connect), and writes
    `DATABASE_URL=postgres:///shorebird?host=/var/run/postgresql&port=5432&user=shorebird&...`:
    a Unix socket with peer authentication, so **no database password exists**.
    An existing role or database with unexpected privileges or owner is refused.
  - `--database-url postgres://USER:PASSWORD@HOST:5432/DB?sslmode=require`: an
    external or managed PostgreSQL; nothing is installed locally.
  - `--sqlite`: a SQLite file, only for small or test installs.
  - `--skip-packages` never runs apt (it fails instead); without apt the
    installer asks you to install PostgreSQL yourself or pass one of the options.

  The server creates and upgrades its PostgreSQL schema itself at start
  (`DB_AUTO_MIGRATE`, default on; goose-compatible `goose_db_version` table).
- **Secrets** in `/etc/shorebird-server/server.env` (root:shorebird 0640),
  created when missing and never replaced: `JWT_SECRET`,
  `PATCH_SIGNING_MASTER_KEY`, `DEFAULT_ADMIN_PASSWORD`, and
  `PATCH_DELIVERY_AES_SECRET` when `PATCH_DELIVERY_ENCRYPTION=per_device_aes_gcm`.
  The generated administrator password is printed once at the end and kept in
  `/etc/shorebird-server/initial-admin-password` (root 0600); it must be
  changed at the first login.
- **Layout**:

  ```
  /var/lib/shorebird-server/bin/shorebird-server   managed image (shorebird, 0755)
  /var/lib/shorebird-server/bin/server-update.json updater settings (shorebird, 0600)
  /var/lib/shorebird-server/data/                  local object storage (and SQLite with --sqlite)
  /usr/local/bin/shorebird-server                  root-owned symlink to the managed image
  /etc/shorebird-server/server.env                 configuration and secrets
  /etc/shorebird-server/server-update-signing.pem  route B only: host update key (root 0600)
  /etc/systemd/system/shorebird-server.service     deploy/systemd/shorebird-server.service
  /etc/caddy/shorebird-server.caddy                with --domain
  ```
- **HTTPS** with `--domain NAME`: sets `SERVER_BASE_URL=https://NAME`, listens on
  `127.0.0.1:8080` (first install), writes `/etc/caddy/shorebird-server.caddy`
  (`reverse_proxy` to the server, `tls --acme-email`) and imports it from the
  Caddyfile (a stock distribution Caddyfile is replaced; any other gets one
  `import` line; backups first), validates and reloads Caddy, which obtains
  the certificate automatically. `--install-caddy` installs Caddy with apt
  when missing (Debian 12+/Ubuntu 24.04+ ship it; otherwise install it from
  caddyserver.com first). Without Caddy it prints the exact Caddy and nginx
  snippets instead.
- **Summary** at the end: URL, admin e-mail and password (once), database,
  service commands, where the keys and configuration live and what to back up.

A rerun is idempotent: it adds only what is missing (for example a secret a
newer release needs) and changes nothing that exists. It refuses to switch the
database, to overwrite a differing managed binary (route A: use the
self-update), symlinked deployment directories and a foreign
`/usr/local/bin/shorebird-server`.

## 4. Connect the shorebird CLI and your app

```sh
export SHOREBIRD_HOSTED_URL=https://patch.example.com   # remembered in the CLI's config
shorebird login                                         # the admin account, then change the password
# CI: an API key (sb_api_...) of a CI account instead of the interactive login
export SHOREBIRD_TOKEN=sb_api_...
```

In the app's `shorebird.yaml` set `base_url: https://patch.example.com` so the
released app fetches patches from your server (hardened releases require an
https `base_url`). The CLI's auth service defaults to
`$SHOREBIRD_HOSTED_URL/auth` (`AUTH_SERVICE_URL` overrides it).

## 5. Operate

| Task | Command |
| --- | --- |
| Status / logs | `systemctl status shorebird-server`, `journalctl -u shorebird-server -f` |
| Health | `curl -fsS http://127.0.0.1:8080/health` (`"database":"postgres"`) |
| Self-update status | `GET /api/v1/admin/server/update` as an administrator (must report `mode: active`) |
| Configuration change | edit `/etc/shorebird-server/server.env`, then `sudo systemctl restart shorebird-server` |
| Upgrade (route A) | `POST /api/v1/admin/server/update/check`, then `POST .../install {"version"}`; or `PUT` `auto_update: true` |
| Upgrade (route B) | `sudo bash install.sh --build-from-source --ref <newer branch/tag/commit>` |
| Roll back | `POST /api/v1/admin/server/update/rollback` with your password (the previous image is kept); a failed trial rolls back by itself and quarantines the version |

Route B upgrades go through the running server: the installer hands the
verified ZIP to the root-only local route (`POST /api/v1/server/update/local`,
authenticated by `/var/lib/shorebird-server/bin/server-local-update.secret`
and loopback only), the server installs it on trial and the installer waits
until the new version runs. The managed binary is never replaced directly.
The listen address must include loopback (`0.0.0.0` or `127.0.0.1`).

### Back up

- `/etc/shorebird-server/` — `server.env` holds `PATCH_SIGNING_MASTER_KEY`,
  which wraps the per-app patch signing keys stored in the database: a
  database backup without it is useless for managed signing. Route B: also the
  host update key (without it, later builds need a reinstall).
- The database: `sudo -u postgres pg_dump -Fc shorebird > shorebird-$(date +%F).dump`
  (restore: `sudo -u postgres pg_restore -d shorebird --clean shorebird-DATE.dump`),
  for example from a daily cron job, copied off the host.
- `/var/lib/shorebird-server/data/` — release and patch artifacts (local storage).

A rollback replaces only the binary; take a database backup before installing
a release with schema migrations if a rollback must stay possible.

### SQLite to PostgreSQL

The server has no export/import, and the installer never converts a database:
switching an existing install is refused because it would start an empty
server. A SQLite install keeps running on SQLite. To move, set up a new
PostgreSQL install and recreate apps/releases there (or migrate the data with
your own tooling), then retire the old host.

## Options

| Option | Meaning |
| --- | --- |
| `--zip FILE`, `--binary FILE` | local signed source instead of a download |
| `--channel auto\|stable\|dev`, `--use-mirror` | download selection (route A) |
| `--build-from-source`, `--ref REF`, `--source-dir DIR`, `--go-root DIR` | route B |
| `--pg-socket DIR`, `--pg-port PORT` | local PostgreSQL cluster (default `/var/run/postgresql`, 5432) |
| `--database-url URL`, `--sqlite`, `--postgres` | database choice (first install; `--postgres` insists on the local one) |
| `--skip-packages` | never run apt |
| `--domain NAME`, `--acme-email EMAIL`, `--install-caddy` | HTTPS through Caddy |
| `--base-url URL` | public URL (default `https://NAME` with `--domain`, else `http://<fqdn>:<port>`) |
| `--listen HOST:PORT` | listen address (first install default `0.0.0.0:8080`, `127.0.0.1:8080` with `--domain`) |
| `--admin-email EMAIL` | bootstrap administrator |
| `--web-dir DIR` | install the dashboard (`web/` of the server archive) into `/var/lib/shorebird-server/web` |
| `--no-start` | install and enable, but do not start |
| `--root DIR`, `--platform P` | stage into `DIR` without users, packages, ownership or systemd (tests) |

`install.sh` is generated: edit `install_body.sh`, `install_lib.py`,
`install_dependencies.sh` and the payloads, then run
`python3 deploy/linux/build_installer.py` (`--check` fails when it is stale).

## Tests

`python3 deploy/linux/test_install.py`: verification refusals, a Go
cross-check with `server-update-tool`, release selection and download, the
database plan (defaults, external URL, SQLite, every refused switch), the
`pg_hba.conf` rule, Caddy files, the host key (created once, never replaced),
source versions, Go toolchain and source downloads (checksum and archive
refusals), dependency detection with fake apt, and staged installs (`--root`)
with fake PostgreSQL tools, a fake Go toolchain and a fake running server for
the route B upgrade (handed to the server, never copied over the binary;
a failed trial is reported). It runs shellcheck when installed.
