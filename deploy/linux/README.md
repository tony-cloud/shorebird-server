# Linux fast installation

`install.sh` installs a self-updating shorebird-server on any Linux host with
systemd (x86_64 or aarch64) in one command. It needs `python3` (3.8 or later)
and the usual base tools; no Go, unzip, OpenSSL or GitHub token.

```sh
curl -fsSL https://raw.githubusercontent.com/tony-cloud/shorebird-server/main/deploy/linux/install.sh | sudo bash -s -- \
    --base-url https://patch.example.com
```

Or download it, read it and run it locally (`sudo bash install.sh --help`).
The file is generated: edit `install_body.sh` and its payloads, then run
`python3 deploy/linux/build_installer.py` (`--check` fails when it is stale).

## What it does

1. **Gets a signed binary** and verifies it before executing anything:
   - by default it reuses the installed managed binary, otherwise downloads
     the newest complete signed release of `tony-cloud/shorebird-server`
     (`--channel auto` prefers stable, falls back to dev; `--use-mirror` tries
     the untrusted TonyCloud mirror first, GitHub is the fallback either way);
   - `--zip FILE` takes the signed update ZIP, `--binary FILE` a raw binary
     with its `FILE.manifest.json` and `FILE.sig`.

   Verification is the server's own (docs/SELF_UPDATE.md): the Ed25519
   signature over the exact manifest bytes, by a key pinned in this
   installer (`signing/server-update.trusted-keys`, written by the operator's
   `scripts/provision_release_keys.py --write-repo-pins` in shorebird-workspace),
   then platform, version and channel, then the binary's size and SHA-256, and
   finally `--version` must print the signed version. The public
   DEVELOPMENT-ONLY key is refused unless `--allow-development` (testing only).
2. **Creates the service account** `shorebird` and the layout:

   ```
   /var/lib/shorebird-server/bin/shorebird-server   managed image (shorebird, 0755)
   /var/lib/shorebird-server/bin/server-update.json updater settings (shorebird, 0600)
   /var/lib/shorebird-server/data/                  SQLite database and local storage
   /usr/local/bin/shorebird-server                  root-owned symlink to the managed image
   /etc/shorebird-server/server.env                 configuration (root:shorebird, 0640)
   /etc/systemd/system/shorebird-server.service     deploy/systemd/shorebird-server.service
   ```
3. **Creates missing runtime secrets** in `server.env` on every run and never
   replaces an existing value: `JWT_SECRET`, `PATCH_SIGNING_MASTER_KEY` (wraps
   the managed patch signing keys; back it up with the database),
   `DEFAULT_ADMIN_PASSWORD` (changed at first login), and
   `PATCH_DELIVERY_AES_SECRET` when `PATCH_DELIVERY_ENCRYPTION=per_device_aes_gcm`.
   The public defaults of the source (`change-me-...`, `admin123`) count as
   missing. An invalid existing `PATCH_SIGNING_MASTER_KEY` stops the install.
   Values are never printed; a changed file is backed up first.
4. **Keeps the updater settings**: `server-update.json` is created once (channel
   of the installed release, `auto_update: false`) and never changed again.
5. **Installs the unit** (backing up a differing one), enables and starts the
   service and waits for `GET /health` on the configured port.

## Reruns and upgrades

A rerun is idempotent: it changes nothing that exists and adds only what is
missing (for example a secret introduced by a newer release). It refuses to
overwrite a managed binary that differs from its source and points to the
signed self-update instead (`GET/POST /api/v1/admin/server/update`, see
docs/SELF_UPDATE.md). It also refuses symlinked deployment directories and a
foreign `/usr/local/bin/shorebird-server`.

## Options

| Option | Meaning |
| --- | --- |
| `--zip FILE`, `--binary FILE` | local signed source instead of a download |
| `--channel auto\|stable\|dev`, `--use-mirror` | download selection |
| `--base-url URL` | public URL (first install default `http://<fqdn>:<port>`) |
| `--listen HOST:PORT` | listen address (first install default `0.0.0.0:8080`) |
| `--admin-email EMAIL` | bootstrap administrator |
| `--web-dir DIR` | install the dashboard (`web/` of the server archive) into `/var/lib/shorebird-server/web` |
| `--no-start` | install and enable, but do not start (for example to switch to PostgreSQL first) |
| `--root DIR`, `--platform P` | stage into `DIR` without users, ownership or systemd (tests) |

The database (SQLite by default; set `DB_DRIVER=postgres` and `DATABASE_URL`),
object storage, TLS and the reverse proxy stay under the operator's control:
edit `server.env` and restart the service.

## Tests

`python3 deploy/linux/test_install.py` covers verification refusals, a Go
cross-check with `server-update-tool`, release selection, download with mirror
fallback, configuration and a staged install with reruns in a temporary
prefix (`--root`), and runs shellcheck when it is installed.
