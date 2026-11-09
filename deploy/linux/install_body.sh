#!/usr/bin/env bash
# shorebird-server one-shot installer for Linux with systemd (docs: deploy/linux/README.md).
# deploy/linux/build_installer.py bundles this file and its payloads into install.sh.
set -Eeuo pipefail
umask 077

usage() {
    cat <<'HELP'
Usage: sudo bash install.sh [options]

Source of the server binary (every source is verified against the pinned
update signing key before it is executed):
  (default)            reuse the installed managed binary, otherwise download the
                       newest signed release of tony-cloud/shorebird-server
  --zip FILE           signed update ZIP (shorebird-server-update-<os>-<arch>-<version>.zip)
  --binary FILE        raw binary with FILE.manifest.json and FILE.sig next to it
  --channel CHANNEL    download channel: auto (stable, else dev), stable or dev
  --use-mirror         try the TonyCloud mirror before GitHub (an untrusted transport)

Configuration (first install defaults; reruns keep existing values unless given):
  --base-url URL       public URL devices and the CLI use (default http://<fqdn>:<port>)
  --listen HOST:PORT   listen address (default 0.0.0.0:8080)
  --admin-email EMAIL  bootstrap administrator e-mail
  --web-dir DIR        install the dashboard (web/ of the server archive)
  --no-start           install and configure, but do not (re)start the service

Testing:
  --root DIR           stage into DIR instead of /: no user, ownership or systemd changes
  --platform P         linux-amd64 or linux-arm64 (default: this machine)
  --allow-development  also trust the public DEVELOPMENT-ONLY update key (never in production)
  --help

The managed binary lives in /var/lib/shorebird-server/bin (owned by the service
user so it can update itself); /usr/local/bin/shorebird-server is a root-owned
symlink to it. Missing runtime secrets (JWT_SECRET, PATCH_SIGNING_MASTER_KEY,
DEFAULT_ADMIN_PASSWORD) are created on every run; existing values, the updater
settings and an installed binary are never replaced. Upgrade an installed
server through its signed self-update (docs/SELF_UPDATE.md), not this script.
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
while (($#)); do
    case "$1" in
        --help|-h) usage; exit 0 ;;
        --use-mirror) use_mirror=true; shift ;;
        --no-start) start=false; shift ;;
        --allow-development) allow_development=true; shift ;;
        --binary|--zip|--channel|--base-url|--listen|--admin-email|--web-dir|--root|--platform)
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
            esac
            shift 2 ;;
        *) fail "Unknown option: $1 (see --help)" ;;
    esac
done
case "$channel" in auto|stable|dev) ;; *) fail 'The channel must be auto, stable or dev.' ;; esac
[[ -z "$binary" || -z "$zip" ]] || fail 'Pass --binary or --zip, not both.'
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
service_user=shorebird

# as_service CMD...: run as the service account (the caller, when staging).
as_service() {
    if $staging; then "$@"; else runuser -u "$service_user" -- "$@"; fi
}

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

if ! $staging; then
    for command in runuser systemctl systemd-analyze flock install useradd groupadd getent cmp; do
        command -v "$command" >/dev/null || fail "Required command missing: $command"
    done
    exec 9>/run/lock/shorebird-server-install.lock
    flock -n 9 || fail 'Another shorebird-server installer is running.'
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
    note "Staging into $root: no user, ownership or systemd changes."
fi

for directory in "$state" "$bin_dir" "$config" "$state/data"; do
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
cleanup() {
    local result=$?
    trap - EXIT
    if $stopped && ((result != 0)); then
        note 'Installation failed after stopping the service; fix the cause, then: systemctl start shorebird-server'
    fi
    case "$stage" in */.shorebird-server-install.*) rm -rf -- "$stage" ;; esac
    exit "$result"
}
trap cleanup EXIT
if ! $staging; then chown "root:$service_user" "$stage"; fi
chmod 0750 "$stage"

verify_args=(--trusted-keys-file "$trusted_keys" --platform "$platform" --output "$stage/server")
if $allow_development; then
    verify_args+=(--allow-development)
    note 'WARNING: the public DEVELOPMENT-ONLY update key is trusted (testing only).'
fi
version=
release_channel=
source_label=
if [[ -n "$zip" ]]; then
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
    source_label="installed $target"
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
    fail "A different managed binary is already installed ($(as_service "$target" --version 2>/dev/null || echo unknown)). Upgrade through the signed self-update: GET/POST /api/v1/admin/server/update (docs/SELF_UPDATE.md)."
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

python3 "$lib" environment --template "$env_template" --output "$env_file" \
    --state-dir "${state#"$root"}" --base-url "$base_url" --listen "$listen" \
    --admin-email "$admin_email" --owner "${owner:+0:$gid}" >/dev/null
port=$(python3 - "$env_file" <<'PY'
import shlex, sys
port = "8080"
for line in open(sys.argv[1], encoding="utf-8"):
    key, _, value = line.strip().partition("=")
    if key == "SERVER_PORT" and value:
        port = (shlex.split(value) or ["8080"])[0]
print(port)
PY
)

if [[ ! -e "$settings" ]]; then
    settings_channel=stable
    if [[ "$release_channel" == dev || "$channel" == dev ]]; then settings_channel=dev; fi
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

if ! $staging && systemctl is-active --quiet shorebird-server; then
    systemctl stop shorebird-server
    stopped=true
fi
if [[ ! -e "$target" ]]; then
    as_service install -m 0755 "$stage/server" "$target"
    printf '%s\n' "$version" | as_service tee "$bin_dir/VERSION" >/dev/null
    note "Installed $target."
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

if $staging; then
    note "Staged shorebird-server $version into $root."
    exit 0
fi
systemd-analyze verify "$unit"
systemctl daemon-reload
if ! $start; then
    systemctl enable shorebird-server >/dev/null
    stopped=false
    note "Installed shorebird-server $version; not started (--no-start). Start it with: systemctl start shorebird-server"
    exit 0
fi
systemctl enable --now shorebird-server
stopped=false
python3 "$lib" health --url "http://127.0.0.1:$port/health" --seconds 120 || \
    fail 'The service did not become healthy. Inspect: journalctl -u shorebird-server -n 100'
cat >&2 <<EOF

Installed shorebird-server $version; http://127.0.0.1:$port/health is healthy.
Configuration:   $env_file (secrets are created only when missing)
Update settings: $settings
Bootstrap admin: read DEFAULT_ADMIN_EMAIL/DEFAULT_ADMIN_PASSWORD privately from $env_file;
                 the password must be changed at the first login.
Self-update:     GET /api/v1/admin/server/update must report mode "active".
EOF
