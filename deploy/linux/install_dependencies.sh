#!/usr/bin/env bash
# Sourced by install_body.sh: finds what the requested setup needs and installs
# only what is missing, from the distribution's packages (apt). Modeled on the
# DaliMaster installer: an existing PostgreSQL (any version, packaged or not,
# running or stopped) is reused and never upgraded; an installed but broken
# package is reported for repair instead of being reinstalled.

shorebird_command_works() {
    command -v "$1" >/dev/null 2>&1 || return 1
    "$1" --version >/dev/null 2>&1
}

shorebird_postgres_present() {
    # SHOREBIRD_DEPENDENCY_ROOT: tests only (an empty prefix is the real system).
    local socket=$1 port=$2 binary prefix=${SHOREBIRD_DEPENDENCY_ROOT:-}
    command -v postgres >/dev/null 2>&1 && return 0
    for binary in "$prefix"/usr/lib/postgresql/*/bin/postgres "$prefix"/usr/local/pgsql/bin/postgres \
        "$prefix"/usr/pgsql-*/bin/postgres; do
        [[ -x "$binary" ]] && return 0
    done
    if command -v pg_lsclusters >/dev/null 2>&1 && [[ -n $(pg_lsclusters --no-header 2>/dev/null) ]]; then
        return 0
    fi
    [[ -S "$socket/.s.PGSQL.$port" ]]
}

# shorebird_install_dependencies SKIP_PACKAGES DB_MODE PG_SOCKET PG_PORT CADDY
#   DB_MODE local needs a PostgreSQL server and psql/createuser/createdb;
#   CADDY true needs caddy. Prints what it does; returns non-zero on a refusal.
shorebird_install_dependencies() {
    local skip_packages=$1 db_mode=$2 pg_socket=$3 pg_port=$4 want_caddy=$5
    local -a missing=()
    local command clients=true candidate

    if [[ "$db_mode" == local ]]; then
        if shorebird_postgres_present "$pg_socket" "$pg_port"; then
            printf 'Reusing the existing PostgreSQL server; no server package is installed.\n' >&2
        else
            missing+=(postgresql)
        fi
        for command in psql createuser createdb; do
            shorebird_command_works "$command" || clients=false
        done
        if ! $clients && [[ " ${missing[*]} " != *' postgresql '* ]]; then
            missing+=(postgresql-client)
        fi
    fi
    if [[ "$want_caddy" == true ]] && ! shorebird_command_works caddy; then
        missing+=(caddy)
    fi
    ((${#missing[@]})) || return 0

    if $skip_packages; then
        printf 'ERROR: missing %s and --skip-packages forbids installing packages. Install them, or use --database-url URL (external PostgreSQL) or --sqlite.\n' "${missing[*]}" >&2
        return 1
    fi
    if ! command -v apt-get >/dev/null 2>&1 || ! command -v dpkg-query >/dev/null 2>&1; then
        printf 'ERROR: missing %s and this is not a Debian/Ubuntu system (no apt). Install them with your package manager and rerun, or use --database-url URL / --sqlite.\n' "${missing[*]}" >&2
        return 1
    fi
    for candidate in "${missing[@]}"; do
        if dpkg-query -W -f='${Status}' "$candidate" 2>/dev/null | grep -q ' ok installed$'; then
            printf 'ERROR: %s is installed but its commands do not work; repair it and rerun.\n' "$candidate" >&2
            return 1
        fi
    done
    printf 'Installing missing packages: %s\n' "${missing[*]}" >&2
    apt-get update || return
    if [[ " ${missing[*]} " == *' caddy '* ]] && ! apt-cache show caddy >/dev/null 2>&1; then
        printf 'ERROR: this distribution has no caddy package. Install Caddy from https://caddyserver.com/docs/install#debian-ubuntu-raspbian and rerun, or drop --install-caddy and configure your own reverse proxy.\n' >&2
        return 1
    fi
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-upgrade "${missing[@]}"
}
