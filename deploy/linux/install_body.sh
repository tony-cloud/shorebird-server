#!/usr/bin/env bash
# shorebird-server one-shot installer for Linux with systemd (docs: deploy/linux/README.md).
# deploy/linux/build_installer.py bundles this file and its payloads into install.sh.
set -Eeuo pipefail
umask 077

usage() {
    cat <<'HELP'
Usage: sudo bash install.sh [options]

Source of the server binary (every source is verified against a pinned update
signing key before it is executed):
  (default)            reuse the installed managed binary, otherwise download the
                       newest signed release of tony-cloud/shorebird-server
  --zip FILE           signed update ZIP (shorebird-server-update-<os>-<arch>-<version>.zip)
  --binary FILE        raw binary with FILE.manifest.json and FILE.sig next to it
  --channel CHANNEL    download channel: auto (stable, else dev), stable or dev
  --use-mirror         try the TonyCloud mirror before GitHub (an untrusted transport)
  --build-from-source  build on this host instead: download the source and the Go
                       toolchain (SHA-256 checked against go.dev), sign with a host-only
                       update key (/etc/shorebird-server/server-update-signing.pem,
                       created once). A rerun with a newer --ref upgrades through the
                       server's self-update transaction (trial, watchdog rollback).
  --ref REF            source commit, branch or tag (default: main); a tag vX.Y.Z
                       builds that stable version, anything else a dev version
  --source-dir DIR     build a local git checkout instead of downloading --ref
  --go-root DIR        use this Go toolchain instead of downloading go.mod's

Database (first install; a rerun keeps the database and refuses to switch):
  (default)            local PostgreSQL (installed with apt when missing): role and
                       database "shorebird", Unix socket, peer authentication, no password
  --pg-socket DIR      local PostgreSQL socket directory (default /var/run/postgresql)
  --pg-port PORT       local PostgreSQL port (default 5432)
  --database-url URL   external/managed PostgreSQL instead (nothing is installed)
  --sqlite             SQLite file instead (small or test installs only)
  --postgres           require the local PostgreSQL (refuses an existing SQLite install)
  --skip-packages      never run apt; fail when something is missing

Public address:
  --domain NAME        serve https://NAME through Caddy (automatic HTTPS); sets the
                       base URL and, on a first install, listens on 127.0.0.1:8080 only
  --acme-email EMAIL   contact for the Let's Encrypt account (with --domain)
  --install-caddy      install Caddy with apt when it is missing (with --domain);
                       without Caddy the exact manual proxy steps are printed

Configuration (first install defaults; reruns keep existing values unless given):
  --base-url URL       public URL devices and the CLI use (default http://<fqdn>:<port>)
  --listen HOST:PORT   listen address (default 0.0.0.0:8080; 127.0.0.1:8080 with --domain)
  --admin-email EMAIL  bootstrap administrator e-mail
  --web-dir DIR        install the dashboard (web/ of the server archive)
  --no-start           install and configure, but do not (re)start the service

Testing:
  --root DIR           stage into DIR instead of /: no user, ownership, package or systemd changes
  --platform P         linux-amd64 or linux-arm64 (default: this machine)
  --allow-development  also trust the public DEVELOPMENT-ONLY update key (never in production)
  --help

The managed binary lives in /var/lib/shorebird-server/bin (owned by the service
user so it can update itself); /usr/local/bin/shorebird-server is a root-owned
symlink to it. Missing runtime secrets (JWT_SECRET, PATCH_SIGNING_MASTER_KEY,
DEFAULT_ADMIN_PASSWORD) are created on every run; existing values, the updater
settings and an installed binary are never replaced. Upgrade an installed
release through its signed self-update (docs/SELF_UPDATE.md), a source build by
rerunning with --build-from-source and a newer --ref.
HELP
}

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
note() { printf '%s\n' "$*" >&2; }

binary=
zip=
channel=auto
use_mirror=false
base_url=
listen=
admin_email=
web_dir=
start=true
root=
platform=
allow_development=false
from_source=false
ref=
source_dir=
go_root=
want_sqlite=false
want_postgres=false
database_url=
pg_socket=
pg_port=
skip_packages=false
domain=
acme_email=
install_caddy=false
while (($#)); do
    case "$1" in
        --help|-h) usage; exit 0 ;;
        --use-mirror) use_mirror=true; shift ;;
        --no-start) start=false; shift ;;
        --allow-development) allow_development=true; shift ;;
        --build-from-source) from_source=true; shift ;;
        --sqlite) want_sqlite=true; shift ;;
        --postgres) want_postgres=true; shift ;;
        --skip-packages) skip_packages=true; shift ;;
        --install-caddy) install_caddy=true; shift ;;
        --binary|--zip|--channel|--base-url|--listen|--admin-email|--web-dir|--root|--platform|--ref|--source-dir|\
        --go-root|--database-url|--pg-socket|--pg-port|--domain|--acme-email)
            (($# >= 2)) && [[ -n "$2" ]] || fail "Missing value for $1"
            case "$1" in
                --binary) binary=$2 ;;
                --zip) zip=$2 ;;
                --channel) channel=$2 ;;
                --base-url) base_url=$2 ;;
                --listen) listen=$2 ;;
                --admin-email) admin_email=$2 ;;
                --web-dir) web_dir=$2 ;;
                --root) root=$2 ;;
                --platform) platform=$2 ;;
                --ref) ref=$2 ;;
                --source-dir) source_dir=$2 ;;
                --go-root) go_root=$2 ;;
                --database-url) database_url=$2 ;;
                --pg-socket) pg_socket=$2 ;;
                --pg-port) pg_port=$2 ;;
                --domain) domain=$2 ;;
                --acme-email) acme_email=$2 ;;
            esac
            shift 2 ;;
        *) fail "Unknown option: $1 (see --help)" ;;
    esac
done
case "$channel" in auto|stable|dev) ;; *) fail 'The channel must be auto, stable or dev.' ;; esac
[[ -z "$binary" || -z "$zip" ]] || fail 'Pass --binary or --zip, not both.'
if $from_source; then
    [[ -z "$binary" && -z "$zip" ]] || fail '--build-from-source builds its own binary; drop --binary/--zip.'
    ! $allow_development || fail '--build-from-source signs with the host key; --allow-development does not apply.'
    [[ -z "$ref" || -z "$source_dir" ]] || fail 'Pass --ref or --source-dir, not both.'
    ref=${ref:-main}
else
    [[ -z "$ref$source_dir$go_root" ]] || fail '--ref, --source-dir and --go-root need --build-from-source.'
fi
if [[ -z "$domain" ]] && { [[ -n "$acme_email" ]] || $install_caddy; }; then
    fail '--acme-email and --install-caddy need --domain.'
fi
command -v python3 >/dev/null || fail 'python3 is required.'

real() { python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$1"; }

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
payload() {
    # Bundled payloads sit next to this script; in a checkout they live in the repository.
    local name=$1 fallback=$2
    if [[ -f "$script_dir/$name" ]]; then printf '%s\n' "$script_dir/$name"
    elif [[ -f "$script_dir/$fallback" ]]; then printf '%s\n' "$script_dir/$fallback"
    else fail "Incomplete installer payload: $name"
    fi
}
lib=$(payload install_lib.py install_lib.py)
dependencies=$(payload install_dependencies.sh install_dependencies.sh)
env_template=$(payload server.env.example server.env.example)
settings_template=$(payload server-update.json server-update.json)
unit_source=$(payload shorebird-server.service ../systemd/shorebird-server.service)
trusted_keys=$(payload server-update.trusted-keys ../../signing/server-update.trusted-keys)

staging=false
if [[ -n "$root" ]]; then
    staging=true
    [[ -d "$root" ]] || fail "--root $root does not exist."
    root=$(real "$root")
    [[ "$root" != / ]] || fail '--root / is the real system; omit --root instead.'
else
    [[ $EUID == 0 ]] || fail 'Run this installer with sudo.'
    [[ $(uname -s) == Linux && -d /run/systemd/system ]] || fail 'Linux with a running systemd is required.'
fi
if [[ -z "$platform" ]]; then
    case "$(uname -m)" in
        x86_64|amd64) platform=linux-amd64 ;;
        aarch64|arm64) platform=linux-arm64 ;;
        *) fail "Unsupported CPU $(uname -m); signed releases exist for linux-amd64 and linux-arm64." ;;
    esac
fi
case "$platform" in linux-amd64|linux-arm64) ;; *) fail 'The platform must be linux-amd64 or linux-arm64.' ;; esac

state=$root/var/lib/shorebird-server
bin_dir=$state/bin
target=$bin_dir/shorebird-server
entry=$root/usr/local/bin/shorebird-server
config=$root/etc/shorebird-server
env_file=$config/server.env
settings=$bin_dir/server-update.json
unit=$root/etc/systemd/system/shorebird-server.service
installer_dir=$root/var/lib/shorebird-server-installer
host_key=$config/server-update-signing.pem
host_trusted=$config/server-update.trusted-keys
source_marker=$config/install-source
initial_password=$config/initial-admin-password
caddyfile=$root/etc/caddy/Caddyfile
caddy_site=$root/etc/caddy/shorebird-server.caddy
service_user=shorebird

# as_service CMD...: run as the service account (the caller, when staging).
as_service() {
    if $staging; then "$@"; else runuser -u "$service_user" -- "$@"; fi
}
# as_postgres CMD...: run as the PostgreSQL superuser account (the caller, when
# staging), from / so the client never tries to read the caller's directory.
as_postgres() {
    if $staging; then "$@"; else (cd / && runuser -u postgres -- "$@"); fi
}

# The database is decided before anything changes: a rerun never switches it.
plan_args=(--env "$env_file")
if $want_sqlite; then plan_args+=(--sqlite); fi
if $want_postgres; then plan_args+=(--postgres); fi
if [[ -n "$database_url" ]]; then plan_args+=(--database-url "$database_url"); fi
if [[ -n "$pg_socket" ]]; then plan_args+=(--pg-socket "$pg_socket"); fi
if [[ -n "$pg_port" ]]; then plan_args+=(--pg-port "$pg_port"); fi
[[ ! -L "$env_file" ]] || fail "Refusing the symlink $env_file"
db_plan=$(python3 "$lib" database-plan "${plan_args[@]}") || exit 1
read -r db_mode db_url pg_socket pg_port <<< "$db_plan"
[[ "$db_url" != - ]] || db_url=
case "$db_mode" in
    local) note "Database: local PostgreSQL (socket $pg_socket, port $pg_port, peer authentication)." ;;
    external) note 'Database: external PostgreSQL (DATABASE_URL).' ;;
    sqlite) note "Database: SQLite (${state#"$root"}/data/shorebird.db)." ;;
esac
if [[ -n "$domain" ]]; then
    domain=$(python3 "$lib" check-domain --domain "$domain") || exit 1
    [[ -n "$base_url" ]] || base_url=https://$domain
fi

if [[ -n "$binary" ]]; then
    [[ -f "$binary" ]] || fail "--binary $binary does not exist."
    binary=$(real "$binary")
    [[ -f "$binary.manifest.json" && -f "$binary.sig" ]] || \
        fail "--binary needs its signed $(basename "$binary").manifest.json and .sig next to it (or use --zip)."
fi
if [[ -n "$zip" ]]; then
    [[ -f "$zip" ]] || fail "--zip $zip does not exist."
    zip=$(real "$zip")
fi
if [[ -n "$web_dir" ]]; then
    [[ -f "$web_dir/index.html" ]] || fail "--web-dir $web_dir has no index.html."
    web_dir=$(real "$web_dir")
fi
if [[ -n "$source_dir" ]]; then
    [[ -d "$source_dir/.git" || -f "$source_dir/.git" ]] || fail "--source-dir $source_dir is not a git checkout."
    source_dir=$(real "$source_dir")
    [[ -z $(git -C "$source_dir" status --porcelain --untracked-files=no) ]] || \
        fail "--source-dir $source_dir has uncommitted changes; commit them first."
fi
if [[ -n "$go_root" ]]; then
    [[ -x "$go_root/bin/go" ]] || fail "--go-root $go_root has no bin/go."
    go_root=$(real "$go_root")
fi
install_source=release
if [[ -f "$source_marker" ]]; then install_source=$(<"$source_marker"); fi
if $from_source && [[ -f "$target" && "$install_source" != source ]]; then
    fail "This server was installed from a signed release; its binary trusts only the release key, so a host build cannot upgrade it. Keep upgrading through the self-update, or reinstall on a fresh host."
fi

if ! $staging; then
    for command in runuser systemctl systemd-analyze flock install useradd groupadd getent cmp; do
        command -v "$command" >/dev/null || fail "Required command missing: $command"
    done
    exec 9>/run/lock/shorebird-server-install.lock
    flock -n 9 || fail 'Another shorebird-server installer is running.'
    want_caddy=false
    if [[ -n "$domain" ]] && $install_caddy; then want_caddy=true; fi
    # shellcheck source=/dev/null
    source "$dependencies"
    shorebird_install_dependencies "$skip_packages" "$db_mode" "$pg_socket" "$pg_port" "$want_caddy" || \
        fail 'Required software is missing (see above); nothing was changed.'
    if ! getent passwd "$service_user" >/dev/null; then
        getent group "$service_user" >/dev/null || groupadd --system "$service_user"
        useradd --system --gid "$service_user" --home-dir /var/lib/shorebird-server \
            --no-create-home --shell /usr/sbin/nologin "$service_user"
        note "Created the system user $service_user."
    fi
    [[ $(id -u "$service_user") != 0 ]] || fail "The $service_user account must not be root."
    uid=$(id -u "$service_user")
    gid=$(id -g "$service_user")
    owner="$uid:$gid"
else
    owner=
    note "Staging into $root: no user, ownership, package or systemd changes."
fi

for directory in "$state" "$bin_dir" "$config" "$state/data" "$installer_dir"; do
    [[ ! -L "$directory" ]] || fail "Refusing a symlinked deployment directory: $directory"
done
mkdir -p "$root/usr/local/bin" "$root/etc/systemd/system" "$root/var/lib"
if $staging; then
    mkdir -p "$config" "$state" "$bin_dir" "$state/data"
    chmod 0750 "$config" "$state" "$bin_dir" "$state/data"
else
    install -d -o root -g "$service_user" -m 0750 "$config"
    install -d -o "$service_user" -g "$service_user" -m 0750 "$state"
    as_service mkdir -p "$bin_dir" "$state/data"
    as_service chmod 0750 "$bin_dir" "$state/data"
fi

# A root-owned staging directory on the same filesystem as the state.
stage=$(mktemp -d "$root/var/lib/.shorebird-server-install.XXXXXXXX")
stopped=false
hba_file=
hba_backup=
pg() { as_postgres psql -X -w -h "$pg_socket" -p "$pg_port" -d postgres -v ON_ERROR_STOP=1 -Atqc "$1"; }
cleanup() {
    local result=$?
    trap - EXIT
    if [[ -n "$hba_backup" ]]; then
        cp -p -- "$hba_backup" "$hba_file"
        pg 'SELECT pg_reload_conf();' >/dev/null 2>&1 || true
        note "Restored $hba_file from $hba_backup."
    fi
    if $stopped && ((result != 0)); then
        note 'Installation failed after stopping the service; fix the cause, then: systemctl start shorebird-server'
    fi
    case "$stage" in */.shorebird-server-install.*) rm -rf -- "$stage" ;; esac
    exit "$result"
}
trap cleanup EXIT
if ! $staging; then chown "root:$service_user" "$stage"; fi
chmod 0750 "$stage"

installed_version=
if [[ -f "$target" && ! -L "$target" ]]; then
    installed_version=$(cd / && as_service "$target" --version 2>/dev/null) || installed_version=
fi

version=
release_channel=
source_label=
upgrade_zip=
upgrade_version=
if $from_source; then
    # Root-only build area: the service account must not be able to swap the
    # toolchain or sources that root builds and signs with.
    mkdir -p "$installer_dir"
    chmod 0700 "$installer_dir"
    if ! $staging; then chown root:root "$installer_dir"; fi
    if [[ -n "$source_dir" ]]; then
        sha=$(git -C "$source_dir" rev-parse HEAD)
        epoch=$(git -C "$source_dir" log -1 --format=%ct HEAD)
        ref=$(git -C "$source_dir" describe --exact-match --tags HEAD 2>/dev/null || true)
        source_tree=$source_dir
        python3 - "$source_tree" "$lib" <<'PY' || fail "--source-dir is not a shorebird-server source tree."
import sys
sys.path.insert(0, __import__("os").path.dirname(sys.argv[2]))
import install_lib
install_lib.check_source(sys.argv[1])
PY
    else
        read -r sha epoch < <(python3 "$lib" resolve-ref --ref "$ref") || fail "Cannot resolve --ref $ref on GitHub."
        source_tree=$stage/source
        python3 "$lib" fetch-source --sha "$sha" --dir "$source_tree" || fail 'The source download failed.'
    fi
    version=$(python3 "$lib" source-version --source "$source_tree" --sha "$sha" --epoch "$epoch" \
        --ref "$ref" --installed "$installed_version") || exit 1
    note "Source ${ref:-$sha} (${sha:0:12}) builds shorebird-server $version."
    order=1
    if [[ -n "$installed_version" ]]; then order=$(python3 "$lib" compare "$version" "$installed_version") || exit 1; fi
    if ((order == 0)); then
        note "shorebird-server $version is already installed; nothing to build."
        version=
    elif ((order < 0)); then
        fail "$version is older than the installed $installed_version; downgrade through the self-update rollback instead (docs/SELF_UPDATE.md)."
    else
        python3 "$lib" host-key --key "$host_key" --trusted "$host_trusted" >/dev/null || \
            fail 'The host update signing key is unusable (see above).'
        expected_go=$(python3 "$lib" go-version --go-mod "$source_tree/go.mod") || exit 1
        if [[ -n "$go_root" ]]; then
            goroot=$go_root
            expected_go=
        else
            mkdir -p "$installer_dir/toolchains"
            goroot=$(python3 "$lib" go-toolchain --go-mod "$source_tree/go.mod" --dir "$installer_dir/toolchains" \
                --platform "$platform") || fail 'The Go toolchain download or verification failed.'
        fi
        python3 "$lib" build --source "$source_tree" --goroot "$goroot" --expected-go "$expected_go" \
            --work "$installer_dir/work" --key "$host_key" --trusted "$host_trusted" --platform "$platform" \
            --version "$version" --epoch "$epoch" --output "$stage/update.zip" || fail 'The build failed; nothing was installed.'
        read -r version release_channel < <(python3 "$lib" verify-zip --trusted-keys-file "$host_trusted" \
            --platform "$platform" --output "$stage/server" --zip "$stage/update.zip") || \
            fail 'The built update failed verification; nothing was installed.'
        source_label="source ${sha:0:12}"
    fi
fi

verify_args=(--trusted-keys-file "$trusted_keys" --platform "$platform" --output "$stage/server")
if $allow_development; then
    verify_args+=(--allow-development)
    note 'WARNING: the public DEVELOPMENT-ONLY update key is trusted (testing only).'
fi
if [[ -n "$source_label" ]]; then
    :
elif [[ -n "$zip" ]]; then
    read -r version release_channel < <(python3 "$lib" verify-zip "${verify_args[@]}" --zip "$zip") || \
        fail 'The update ZIP failed verification; nothing was installed.'
    source_label="$zip"
elif [[ -n "$binary" ]]; then
    read -r version release_channel < <(python3 "$lib" verify "${verify_args[@]}" --binary "$binary" \
        --manifest "$binary.manifest.json" --signature "$binary.sig") || \
        fail 'The binary failed verification; nothing was installed.'
    source_label="$binary"
elif [[ -f "$target" && ! -L "$target" ]]; then
    cp -- "$target" "$stage/server"
    version=
    source_label="installed $target"
elif $from_source; then
    fail 'Nothing to install.'
else
    download_args=("${verify_args[@]}" --channel "$channel")
    if $use_mirror; then download_args+=(--use-mirror); fi
    read -r version release_channel < <(python3 "$lib" download "${download_args[@]}") || \
        fail 'Download or verification failed; nothing was installed.'
    source_label="release $version"
fi
[[ -n "$version" || "$source_label" == installed* ]] || fail 'Verification produced no version.'

[[ ! -L "$target" ]] || fail "The managed binary $target must be a regular file, not a symlink."
if [[ -f "$target" ]] && ! cmp -s -- "$stage/server" "$target"; then
    if ! $from_source; then
        fail "A different managed binary is already installed (${installed_version:-unknown}). Upgrade through the signed self-update: GET/POST /api/v1/admin/server/update (docs/SELF_UPDATE.md)."
    fi
    # Host build of a newer version: the running server installs it through
    # its own transaction (trial, watchdog rollback, quarantine) at the end.
    upgrade_zip=$stage/update.zip
    upgrade_version=$version
    cp -- "$target" "$stage/server"
    version=
    source_label="installed $target (upgrade to $upgrade_version follows)"
fi
if [[ -L "$entry" ]]; then
    [[ $(readlink "$entry") == "${target#"$root"}" ]] || fail "$entry is a symlink to another file; remove it first."
elif [[ -e "$entry" ]]; then
    fail "$entry is a regular file; move it aside (the managed entry point is a symlink)."
fi

chmod 0755 "$stage/server"
probe=$(cd / && as_service "$stage/server" --version) || fail 'The binary does not run on this machine.'
[[ -n "$probe" && "$probe" != *$'\n'* ]] || fail 'The binary printed an invalid version.'
if [[ -n "$version" && "$probe" != "$version" ]]; then
    fail "The binary reports $probe but its signed manifest says $version."
fi
version=$probe
note "Verified shorebird-server $version ($source_label)."

default_listen=
if [[ -n "$domain" ]]; then default_listen=127.0.0.1:8080; fi
db_driver=postgres
if [[ "$db_mode" == sqlite ]]; then db_driver=sqlite; fi
python3 "$lib" environment --template "$env_template" --output "$env_file" \
    --state-dir "${state#"$root"}" --base-url "$base_url" --listen "$listen" --default-listen "$default_listen" \
    --admin-email "$admin_email" --owner "${owner:+0:$gid}" --db-driver "$db_driver" --db-url "$db_url" \
    --reveal "$stage/admin-password" >/dev/null
read -r listen_host port admin_address public_url < <(python3 - "$env_file" <<'PY'
import shlex, sys
values = {}
for line in open(sys.argv[1], encoding="utf-8"):
    key, _, value = line.strip().partition("=")
    if key and not key.startswith("#"):
        values[key] = (shlex.split(value) or [""])[0]
print(values.get("SERVER_HOST") or "0.0.0.0", values.get("SERVER_PORT") or "8080",
      values.get("DEFAULT_ADMIN_EMAIL") or "-", values.get("SERVER_BASE_URL") or "-")
PY
)
case "$listen_host" in
    0.0.0.0|"") local_host=127.0.0.1 ;;
    ::|"[::]") local_host='[::1]' ;;
    *:*) local_host="[$listen_host]" ;;
    *) local_host=$listen_host ;;
esac
local_url=http://$local_host:$port

if [[ ! -e "$settings" ]]; then
    settings_channel=stable
    if [[ "$release_channel" == dev || "$channel" == dev || "$version" == *-* ]]; then settings_channel=dev; fi
    python3 "$lib" update-settings --template "$settings_template" --output "$stage/server-update.json" \
        --channel "$settings_channel" --use-mirror "$use_mirror" --display "$settings"
    if $staging; then
        cp -- "$stage/server-update.json" "$settings"
        chmod 0600 "$settings"
    else
        chmod 0644 "$stage/server-update.json"
        as_service install -m 0600 "$stage/server-update.json" "$settings"
    fi
else
    note "$settings: kept (administrator settings are never replaced)."
fi

if [[ "$db_mode" == local ]]; then
    note 'Configuring the local PostgreSQL...'
    if ! $staging && systemctl list-unit-files postgresql.service >/dev/null 2>&1; then
        systemctl enable --now postgresql >/dev/null 2>&1 || true
    fi
    ready=false
    attempts=30
    if $staging; then attempts=3; fi
    for ((attempt = 0; attempt < attempts; attempt++)); do
        if pg 'SELECT 1;' >/dev/null 2>&1; then ready=true; break; fi
        sleep 1
    done
    $ready || fail "PostgreSQL does not answer on $pg_socket port $pg_port; start it, or pass --pg-socket/--pg-port, --database-url or --sqlite."
    if [[ $(pg "SELECT count(*) FROM pg_roles WHERE rolname='shorebird';") == 0 ]]; then
        as_postgres createuser -w -h "$pg_socket" -p "$pg_port" --no-superuser --no-createdb --no-createrole shorebird
        note 'Created the PostgreSQL role shorebird (no password; peer authentication).'
    fi
    [[ $(pg "SELECT rolcanlogin AND NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls) FROM pg_roles WHERE rolname='shorebird';") == t ]] || \
        fail 'The existing PostgreSQL role shorebird is not a restricted login role; review it manually.'
    if [[ $(pg "SELECT count(*) FROM pg_database WHERE datname='shorebird';") == 0 ]]; then
        as_postgres createdb -w -h "$pg_socket" -p "$pg_port" --owner=shorebird shorebird
        note 'Created the PostgreSQL database shorebird.'
    fi
    [[ $(pg "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='shorebird';") == shorebird ]] || \
        fail 'The existing database shorebird has another owner; refusing to change it.'
    [[ $(pg 'SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL;') == 0 ]] || \
        fail 'The existing pg_hba.conf has errors; fix them first.'
    hba_file=$(pg 'SHOW hba_file;')
    hba_backup=$(python3 "$lib" hba --output "$hba_file") || fail "Cannot update $hba_file."
    if [[ -n "$hba_backup" ]]; then
        note "Added the shorebird peer rule to $hba_file (backup: $hba_backup)."
        [[ $(pg 'SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL;') == 0 ]] || \
            fail 'pg_hba.conf validation failed; restoring the backup.'
        [[ $(pg 'SELECT pg_reload_conf();') == t ]] || fail 'PostgreSQL reload failed; restoring the backup.'
    fi
    ready=false
    for ((attempt = 0; attempt < 10; attempt++)); do
        if [[ $(cd / && as_service psql -X -w -h "$pg_socket" -p "$pg_port" -d shorebird -Atqc \
            "SELECT current_user='shorebird' AND inet_client_addr() IS NULL;" 2>/dev/null) == t ]]; then
            ready=true; break
        fi
        sleep 1
    done
    $ready || fail 'The service account cannot reach PostgreSQL with peer authentication; restoring pg_hba.conf.'
    hba_backup=  # verified: the backup stays on disk, no automatic restore any more
fi

if ! $staging && systemctl is-active --quiet shorebird-server; then
    systemctl stop shorebird-server
    stopped=true
fi
if [[ ! -e "$target" ]]; then
    as_service install -m 0755 "$stage/server" "$target"
    printf '%s\n' "$version" | as_service tee "$bin_dir/VERSION" >/dev/null
    note "Installed $target."
    install_source=release
    if $from_source; then install_source=source; fi
    printf '%s\n' "$install_source" > "$source_marker"
    chmod 0644 "$source_marker"
else
    note "$target: unchanged."
fi
if [[ ! -L "$entry" ]]; then
    ln -s -- "${target#"$root"}" "$entry"
    note "Linked $entry -> ${target#"$root"}."
fi
if [[ -n "$web_dir" ]]; then
    rm -rf -- "$stage/web"
    cp -R -- "$web_dir" "$stage/web"
    if [[ -d "$state/web" ]]; then rm -rf -- "$state/web.previous"; mv -- "$state/web" "$state/web.previous"; fi
    mv -- "$stage/web" "$state/web"
    if ! $staging; then chown -R "root:$service_user" "$state/web"; fi
    chmod -R u=rwX,g=rX,o= "$state/web"
    note "Installed the dashboard into $state/web."
fi
if [[ -f "$unit" ]] && ! cmp -s "$unit" "$unit_source"; then
    cp -p -- "$unit" "$unit.before-install-$(date +%s)"
fi
if ! cmp -s "$unit" "$unit_source" 2>/dev/null; then
    cp -- "$unit_source" "$unit"
    chmod 0644 "$unit"
    note "Installed $unit."
fi
if [[ -s "$stage/admin-password" && ! -e "$initial_password" ]]; then
    cp -- "$stage/admin-password" "$initial_password"
    chmod 0600 "$initial_password"
    if ! $staging; then chown root:root "$initial_password"; fi
fi

# Reverse proxy: Caddy with automatic HTTPS for --domain.
proxy_note=
if [[ -n "$domain" ]]; then
    upstream=$local_host:$port
    if command -v caddy >/dev/null 2>&1 || $staging; then
        caddy_backups=$(python3 "$lib" caddy --domain "$domain" --upstream "$upstream" --acme-email "$acme_email" \
            --caddyfile "$caddyfile" --site-file "$caddy_site" --import-path "${caddy_site#"$root"}") || \
            fail 'Writing the Caddy configuration failed.'
        if ! $staging; then
            if ! caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >"$stage/caddy.log" 2>&1; then
                while IFS= read -r backup; do
                    [[ -n "$backup" ]] && cp -p -- "$backup" "${backup%.before-shorebird-*}"
                done <<< "$caddy_backups"
                cat "$stage/caddy.log" >&2
                fail 'The Caddy configuration does not validate; the previous files were restored.'
            fi
            systemctl enable caddy >/dev/null 2>&1 || true
            if systemctl is-active --quiet caddy; then systemctl reload caddy; else systemctl start caddy; fi
        fi
        proxy_note="Caddy serves https://$domain -> $upstream (${caddy_site#"$root"}); open TCP 80 and 443."
    else
        proxy_note="Caddy is not installed: rerun with --install-caddy, or point your reverse proxy at $upstream:
    Caddy:  $domain { reverse_proxy $upstream }      (in /etc/caddy/Caddyfile)
    nginx:  server { listen 443 ssl; server_name $domain; client_max_body_size 1g;
                     location / { proxy_pass http://$upstream; proxy_set_header Host \$host;
                                  proxy_set_header X-Forwarded-Proto \$scheme; } }
  Then open TCP 80 and 443 and point the DNS name $domain at this host."
    fi
fi

summary() {
    local status=$1 password_line database_line backup_db
    if [[ -s "$stage/admin-password" ]]; then
        password_line="$(<"$stage/admin-password")   <- shown once; also in ${initial_password#"$root"} (root, 0600)"
    elif [[ -f "$initial_password" ]]; then
        password_line="(not shown again) see ${initial_password#"$root"} if it was never changed"
    else
        password_line="(not shown) DEFAULT_ADMIN_PASSWORD in ${env_file#"$root"} if it was never changed"
    fi
    case "$db_mode" in
        local) database_line="PostgreSQL database shorebird, local socket $pg_socket:$pg_port, peer auth (no password)"
               backup_db="sudo -u postgres pg_dump -Fc shorebird > shorebird-\$(date +%F).dump" ;;
        external) database_line='PostgreSQL at DATABASE_URL (external)'
                  backup_db="your provider's backups, or: pg_dump -Fc \"\$DATABASE_URL\" > shorebird.dump" ;;
        *) database_line="SQLite ${state#"$root"}/data/shorebird.db (small installs only)"
           backup_db="stop the service and copy ${state#"$root"}/data/shorebird.db*" ;;
    esac
    cat >&2 <<EOF

==== shorebird-server $version: $status ====
Public URL:      ${public_url}
Local check:     curl $local_url/health
Admin e-mail:    ${admin_address}
Admin password:  ${password_line}
                 The password must be changed at the first login.
Database:        ${database_line}
Service:         systemctl status shorebird-server | journalctl -u shorebird-server -f
Configuration:   ${env_file#"$root"} (secrets, root:shorebird 0640)
EOF
    if $from_source || [[ "$install_source" == source ]]; then
        cat >&2 <<EOF
Update key:      ${host_key#"$root"} (root 0600, signs this host's builds) and ${host_trusted#"$root"}
Upgrade:         rerun with --build-from-source --ref NEWER (the server installs it on trial
                 and rolls back automatically); GitHub releases are not trusted by this build.
EOF
    else
        cat >&2 <<EOF
Upgrade:         GET/POST /api/v1/admin/server/update (signed GitHub releases, docs/SELF_UPDATE.md)
EOF
    fi
    cat >&2 <<EOF
Back up:         ${config#"$root"}/ (server.env holds PATCH_SIGNING_MASTER_KEY: without it the
                 patch signing keys in the database are lost), ${state#"$root"}/data/ (storage),
                 and the database: ${backup_db}
Connect the CLI: export SHOREBIRD_HOSTED_URL=${public_url}; shorebird login
                 (CI: SHOREBIRD_TOKEN=<sb_api_ key>); set base_url: ${public_url} in shorebird.yaml
EOF
    if [[ -n "$proxy_note" ]]; then printf 'Proxy:           %s\n' "$proxy_note" >&2; fi
}

run_upgrade() {
    [[ -n "$upgrade_zip" ]] || return 0
    read -r version _ < <(python3 "$lib" local-update --zip "$upgrade_zip" --url "$local_url" --bin-dir "$bin_dir" \
        --version "$upgrade_version") || fail "The upgrade to $upgrade_version did not complete (the running version is unchanged unless the log says otherwise)."
    note "Upgraded to $version; it is on trial and rolls back automatically if it fails."
}

if $staging; then
    run_upgrade
    note "Staged shorebird-server $version into $root."
    summary staged
    exit 0
fi
systemd-analyze verify "$unit"
systemctl daemon-reload
if ! $start; then
    systemctl enable shorebird-server >/dev/null
    stopped=false
    summary 'installed, not started (--no-start); start it with: systemctl start shorebird-server'
    exit 0
fi
systemctl enable --now shorebird-server
stopped=false
python3 "$lib" health --url "$local_url/health" --seconds 120 || \
    fail 'The service did not become healthy. Inspect: journalctl -u shorebird-server -n 100'
run_upgrade
summary "running, $local_url/health is healthy"
