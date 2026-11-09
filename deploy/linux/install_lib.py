#!/usr/bin/env python3
"""shorebird-server installer helpers: signed release download/verification and
runtime configuration. Standard library only; never prints a secret value.

The update trust contract is the server's own (internal/updater, docs/SELF_UPDATE.md):
`<asset>.sig` is {"key_id","signature"} over
`open-shorebird.server-update-signature.v1:<hex SHA-256 of the exact manifest bytes>`,
Ed25519, by a key pinned in server-update.trusted-keys. Nothing in a manifest is
trusted before its signature verifies, and the binary is used only after its
size and SHA-256 match the signed manifest.
"""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

PRODUCT = "shorebird-server"
REPOSITORY = "tony-cloud/shorebird-server"
MIRROR = "https://mirrors.tonycloud.cn/"
SIGNATURE_DOMAIN = b"open-shorebird.server-update-signature.v1:"
DEVELOPMENT_PUBLIC_KEY = "a0ZEK+btwcAvqSxqsi4jT7YFIVj9AecHhANwfESYE4w="
PLATFORMS = ("linux-amd64", "linux-arm64")
MAX_BINARY = 128 << 20
MAX_MANIFEST = 16 << 10
MAX_SIGNATURE = 1024
MAX_ZIP = 130 << 20
VERSION = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
                     r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
                     r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?")
MANIFEST_FIELDS = {"product", "version", "channel", "goos", "goarch", "asset", "sha256", "size"}
# The known insecure defaults of internal/config: treated as missing.
INSECURE_DEFAULTS = {
    "JWT_SECRET": {"change-me-in-production-use-a-long-random-string"},
    "DEFAULT_ADMIN_PASSWORD": {"admin123"},
}


class InstallError(Exception):
    pass


# ---------------------------------------------------------------------------
# Ed25519 verification (RFC 8032), pure Python so the installer needs no
# OpenSSL feature level or third-party package.

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _add(p1, p2):
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * 2 * _D * t2 % _P
    d = z1 * 2 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(scalar, point):
    result = (0, 1, 1, 0)
    while scalar:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _equal(p1, p2):
    return (p1[0] * p2[2] - p2[0] * p1[2]) % _P == 0 and (p1[1] * p2[2] - p2[1] * p1[2]) % _P == 0


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _I % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _decompress(data):
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


_GY = 4 * pow(5, _P - 2, _P) % _P
_G = (_recover_x(_GY, 0), _GY, 1, _recover_x(_GY, 0) * _GY % _P)


def ed25519_verify(public, message, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _decompress(public)
    r = _decompress(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a is None or r is None or s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _L
    return _equal(_mul(s, _G), _add(r, _mul(h, a)))


# ---------------------------------------------------------------------------
# Trust and verification


def key_id(public):
    return "sha256:" + hashlib.sha256(public).hexdigest()


def canonical_b64(value, size, what):
    if not isinstance(value, str):
        raise InstallError(f"{what} is not a string")
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError:
        raise InstallError(f"{what} is not base64") from None
    if len(raw) != size or base64.b64encode(raw).decode("ascii") != value:
        raise InstallError(f"{what} is malformed")
    return raw


def load_trusted_keys(path, allow_development):
    """{key id: public key} from a pin file (one base64 key per line, # comments)."""
    keys = {}
    for line in Path(path).read_text(encoding="ascii").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        for entry in line.split(","):
            entry = entry.strip()
            if not entry:
                continue
            raw = canonical_b64(entry, 32, "trusted key")
            if _decompress(raw) is None:
                raise InstallError("a trusted key is not an Ed25519 public key")
            if entry == DEVELOPMENT_PUBLIC_KEY and not allow_development:
                raise InstallError("the DEVELOPMENT-ONLY update key is pinned; refusing (testing needs --allow-development)")
            if key_id(raw) in keys and entry != DEVELOPMENT_PUBLIC_KEY:
                raise InstallError("a trusted key is listed twice")
            keys[key_id(raw)] = raw
    if allow_development:
        # Testing only: additionally trust the committed, public DEVELOPMENT-ONLY key.
        development = base64.b64decode(DEVELOPMENT_PUBLIC_KEY)
        keys[key_id(development)] = development
    if not keys:
        raise InstallError("this installer pins no production update key yet; the operator provisions it with "
                           "scripts/provision_release_keys.py --write-repo-pins in shorebird-workspace")
    return keys


def strict_object(data, fields, what):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise InstallError(f"{what} repeats {key}")
            result[key] = value
        return result
    try:
        document = json.loads(data.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, ValueError):
        raise InstallError(f"{what} is not JSON") from None
    if not isinstance(document, dict) or set(document) != fields:
        raise InstallError(f"{what} has unexpected fields")
    return document


def version_key(version):
    match = VERSION.fullmatch(version or "")
    if not match:
        raise ValueError("invalid version")
    major, minor, patch, pre = match.groups()
    identifiers = () if pre is None else tuple(
        (0, int(part), "") if part.isdigit() else (1, 0, part) for part in pre.split("."))
    return int(major), int(minor), int(patch), pre is None, identifiers


def verify_manifest(manifest, signature, platform, trusted):
    """The verified manifest dict. Signature first; then every field."""
    if len(manifest) > MAX_MANIFEST or len(signature) > MAX_SIGNATURE:
        raise InstallError("manifest or signature is too large")
    sig = strict_object(signature, {"key_id", "signature"}, "signature file")
    raw = canonical_b64(sig["signature"], 64, "signature")
    public = trusted.get(sig["key_id"])
    if public is None:
        raise InstallError(f"untrusted_signer: {sig['key_id']} is not a pinned update key")
    message = SIGNATURE_DOMAIN + hashlib.sha256(manifest).hexdigest().encode("ascii")
    if not ed25519_verify(public, message, raw):
        raise InstallError("signature_invalid: the manifest signature does not verify")
    m = strict_object(manifest, MANIFEST_FIELDS, "manifest")
    goos, goarch = platform.split("-")
    try:
        key = version_key(m["version"])
    except ValueError:
        raise InstallError("invalid_release: bad version") from None
    stable = key[3]
    if (m["product"] != PRODUCT or m["channel"] not in ("stable", "dev")
            or (m["channel"] == "stable") != stable
            or type(m["size"]) is not int or not 0 < m["size"] <= MAX_BINARY
            or not isinstance(m["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", m["sha256"])):
        raise InstallError("invalid_release: manifest fields are invalid")
    if m["goos"] != goos or m["goarch"] != goarch or m["asset"] != f"{PRODUCT}-{platform}":
        raise InstallError(f"wrong_platform: the release is for {m['goos']}-{m['goarch']}, not {platform}")
    return m


def check_binary(path, manifest):
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 16), b""):
            size += len(block)
            if size > MAX_BINARY:
                break
            digest.update(block)
    if size != manifest["size"] or digest.hexdigest() != manifest["sha256"]:
        raise InstallError("checksum_mismatch: the binary does not match its signed manifest")


def verify_files(binary, manifest_path, signature_path, platform, trusted, output):
    manifest = verify_manifest(Path(manifest_path).read_bytes(), Path(signature_path).read_bytes(), platform, trusted)
    check_binary(binary, manifest)
    shutil.copyfile(binary, output)
    check_binary(output, manifest)  # the copy, not just the source, is what was verified
    return manifest


def verify_zip(path, platform, trusted, output):
    """Verifies an update ZIP exactly like the server's upload route; extracts the binary."""
    asset = f"{PRODUCT}-{platform}"
    expected = {asset, asset + ".manifest.json", asset + ".sig", "VERSION"}
    if os.path.getsize(path) > MAX_ZIP:
        raise InstallError("invalid_zip: too large")
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        raise InstallError("invalid_zip: not a ZIP file") from None
    with archive:
        names = [info.filename for info in archive.infolist()]
        if sorted(names) != sorted(expected) or len(names) != len(set(names)):
            raise InstallError(f"invalid_zip: expected exactly {sorted(expected)}")
        limits = {asset: MAX_BINARY, asset + ".manifest.json": MAX_MANIFEST, asset + ".sig": MAX_SIGNATURE,
                  "VERSION": 256}

        def read(name):
            with archive.open(name) as stream:
                data = stream.read(limits[name] + 1)
            if len(data) > limits[name]:
                raise InstallError(f"invalid_zip: {name} is too large")
            return data
        manifest = verify_manifest(read(asset + ".manifest.json"), read(asset + ".sig"), platform, trusted)
        if read("VERSION").decode("ascii", "replace").strip() != manifest["version"]:
            raise InstallError("version_mismatch: VERSION differs from the signed manifest")
        with archive.open(asset) as source, open(output, "wb") as target:
            remaining = MAX_BINARY + 1
            while remaining > 0:
                block = source.read(min(1 << 16, remaining))
                if not block:
                    break
                remaining -= len(block)
                target.write(block)
    check_binary(output, manifest)
    return manifest


# ---------------------------------------------------------------------------
# Release download (GitHub, optional untrusted mirror)


GITHUB_HOSTS = ("github.com", "api.github.com", "codeload.github.com")
GO_HOSTS = ("go.dev", "dl.google.com")


def allowed_url(url, hosts=None):
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or ""
    if parsed.scheme != "https" or parsed.username is not None or parsed.password is not None:
        return False
    if hosts is not None:
        return host in hosts
    return (host in GITHUB_HOSTS or host == urllib.parse.urlsplit(MIRROR).hostname
            or host.endswith(".githubusercontent.com"))


class _Redirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, hosts=None):
        super().__init__()
        self.hosts = hosts

    def redirect_request(self, request, fp, code, message, headers, new_url):
        if not allowed_url(new_url, self.hosts):
            raise InstallError("redirect refused")
        return super().redirect_request(request, fp, code, message, headers, new_url)


def download(url, destination, limit, use_mirror, opener=None, *, hosts=None, seconds=300, accept=None):
    """Downloads `url` (GitHub, or `hosts`) with size and time limits. GitHub URLs
    fall back to (or, with use_mirror, start at) the untrusted mirror; whatever
    arrives is verified by the caller."""
    if not allowed_url(url, hosts):
        raise InstallError("download URL refused")
    targets = [url]
    if hosts is None:
        mirrored = MIRROR + url[len("https://"):]
        targets = [mirrored, url] if use_mirror else [url, mirrored]
    opener = opener or urllib.request.build_opener(_Redirects(hosts))
    last = None
    for target in targets:
        try:
            headers = {"User-Agent": "shorebird-server-installer"}
            if accept:
                headers["Accept"] = accept
            request = urllib.request.Request(target, headers=headers)
            deadline = time.monotonic() + seconds
            with opener.open(request, timeout=30) as response, open(destination, "wb") as output:
                size = 0
                while True:
                    data = response.read(min(1 << 16, limit + 1 - size))
                    if not data:
                        return
                    size += len(data)
                    if size > limit or time.monotonic() > deadline:
                        raise InstallError("download exceeds its size or time limit")
                    output.write(data)
        except (OSError, urllib.error.URLError, InstallError, ValueError) as error:
            last = error
            Path(destination).unlink(missing_ok=True)
    raise InstallError(f"download of {url} failed: {last}")


def select_release(releases, channel, asset):
    candidates = []
    for release in releases if isinstance(releases, list) else []:
        if not isinstance(release, dict) or release.get("draft"):
            continue
        try:
            key = version_key(release.get("tag_name", ""))
        except (ValueError, TypeError):
            continue
        stable = key[3] and not release.get("prerelease")
        names = [a.get("name") for a in release.get("assets", []) if isinstance(a, dict) and a.get("state") == "uploaded"]
        if any(names.count(name) != 1 for name in (asset, asset + ".manifest.json", asset + ".sig")):
            continue
        if channel != "stable" or stable:
            candidates.append((key, stable, release))
    if channel == "auto" and any(item[1] for item in candidates):
        candidates = [item for item in candidates if item[1]]
    if not candidates:
        raise InstallError(f"no complete signed {channel} release of {REPOSITORY} for {asset}")
    return max(candidates, key=lambda item: item[0])[2]


def download_release(output, platform, channel, use_mirror, trusted, opener=None):
    asset = f"{PRODUCT}-{platform}"
    with tempfile.TemporaryDirectory(prefix="shorebird-release-", dir=str(Path(output).parent)) as temporary:
        directory = Path(temporary)
        download(f"https://api.github.com/repos/{REPOSITORY}/releases?per_page=100", directory / "releases.json",
                 4 << 20, use_mirror, opener)
        try:
            releases = json.loads((directory / "releases.json").read_bytes())
        except ValueError:
            raise InstallError("the release list is not JSON") from None
        release = select_release(releases, channel, asset)
        tag = release["tag_name"]
        base = f"https://github.com/{REPOSITORY}/releases/download/{urllib.parse.quote(tag, safe='')}/{asset}"
        download(base + ".manifest.json", directory / "manifest", MAX_MANIFEST, use_mirror, opener)
        download(base + ".sig", directory / "signature", MAX_SIGNATURE, use_mirror, opener)
        manifest = verify_manifest((directory / "manifest").read_bytes(), (directory / "signature").read_bytes(),
                                   platform, trusted)
        if manifest["version"] != tag:
            raise InstallError("version_mismatch: the release tag differs from its signed manifest")
        if channel == "auto" and manifest["channel"] == "dev":
            print("note: no stable release is published; installing the newest signed dev release", file=sys.stderr)
        print(f"Downloading {tag} for {platform}...", file=sys.stderr)
        download(base, directory / "binary", manifest["size"], use_mirror, opener)
        check_binary(directory / "binary", manifest)
        (directory / "binary").replace(output)
    return manifest


# ---------------------------------------------------------------------------
# Runtime configuration (server.env)


def say(text):
    """Progress for the operator; stdout stays machine-readable."""
    print(text, file=sys.stderr)


def env_values(text):
    values = {}
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, separator, raw = stripped.partition("=")
        if not separator or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise InstallError(f"server.env line {number}: expected KEY=value")
        if key in values:
            raise InstallError(f"server.env repeats {key}")
        try:
            parsed = shlex.split(raw, comments=False)
        except ValueError:
            raise InstallError(f"server.env {key}: unbalanced quotes") from None
        if len(parsed) > 1:
            raise InstallError(f"server.env {key}: quote values containing spaces")
        values[key] = parsed[0] if parsed else ""
    return values


def replace_values(text, changes):
    lines = []
    remaining = dict(changes)
    for line in text.splitlines():
        key = line.partition("=")[0].strip()
        if key in remaining and not line.lstrip().startswith("#"):
            line = f"{key}={shlex.quote(remaining.pop(key))}"
        lines.append(line)
    lines.extend(f"{key}={shlex.quote(value)}" for key, value in remaining.items())
    return "\n".join(lines) + "\n"


def atomic_write(path, data, mode, uid=None, gid=None):
    path = Path(path)
    if path.is_symlink():
        raise InstallError(f"refusing to replace the symlink {path}")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            if uid is not None:
                os.fchown(stream.fileno(), uid, gid)
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def listen_address(value):
    host, separator, port = value.rpartition(":")
    if not separator or not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise InstallError("--listen expects HOST:PORT")
    return host.strip("[]"), port


def base_url(value):
    url = urllib.parse.urlsplit(value)
    if (url.scheme not in ("http", "https") or not url.hostname or url.username or url.password
            or url.query or url.fragment or url.path not in ("", "/")):
        raise InstallError("--base-url expects http(s)://HOST[:PORT] without a path")
    return value.rstrip("/")


def prepare_environment(template, output, state_dir, *, base=None, listen=None, admin_email=None, owner=None,
                        default_listen=None, db_driver=None, db_url=None, reveal=None):
    """Creates missing secrets and settings; existing values are never replaced.
    The database is set on a new file (or where it is missing): database_plan()
    already refused every switch. A generated administrator password is also
    written to `reveal` (0600, created once) so the installer can show it."""
    output = Path(output)
    if output.is_symlink():
        raise InstallError(f"refusing the symlink {output}")
    existing = output.exists()
    text = output.read_text(encoding="utf-8") if existing else (
        Path(template).read_text(encoding="utf-8").replace("@STATE_DIR@", str(state_dir)))
    values = env_values(text)
    changes = {}
    created = []
    if not existing or listen:
        host, port = listen_address(listen or default_listen or "0.0.0.0:8080")
        changes.update(SERVER_HOST=host, SERVER_PORT=port)
    port = changes.get("SERVER_PORT") or values.get("SERVER_PORT") or "8080"
    if not existing or base:
        changes["SERVER_BASE_URL"] = base_url(base or f"http://{socket.getfqdn() or 'localhost'}:{port}")
    if admin_email:
        if not re.fullmatch(r"[^@\s]+@[^@\s]+", admin_email):
            raise InstallError("--admin-email is not an e-mail address")
        changes["DEFAULT_ADMIN_EMAIL"] = admin_email
    if db_driver and (not existing or not values.get("DB_DRIVER")):
        changes["DB_DRIVER"] = db_driver
    if db_url and (not existing or not values.get("DATABASE_URL")):
        changes["DATABASE_URL"] = db_url
    # Secrets: created when missing (or a known insecure default); never replaced.
    generators = {
        "JWT_SECRET": lambda: secrets.token_hex(32),
        "PATCH_SIGNING_MASTER_KEY": lambda: base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        "DEFAULT_ADMIN_PASSWORD": lambda: secrets.token_urlsafe(24),
    }
    if values.get("PATCH_DELIVERY_ENCRYPTION") == "per_device_aes_gcm":
        generators["PATCH_DELIVERY_AES_SECRET"] = lambda: secrets.token_hex(32)
    notes = []
    for name, generate in generators.items():
        current = values.get(name, "")
        if current and current not in INSECURE_DEFAULTS.get(name, ()):
            continue
        if current and existing and name == "JWT_SECRET":
            notes.append("JWT_SECRET was the public default; a new one signs out every session")
        changes[name] = generate()
        created.append(name)
    master = changes.get("PATCH_SIGNING_MASTER_KEY", values.get("PATCH_SIGNING_MASTER_KEY", ""))
    try:
        valid = len(base64.b64decode(master, validate=True)) == 32
    except ValueError:
        valid = False
    if not valid:
        raise InstallError("the existing PATCH_SIGNING_MASTER_KEY is not base64 of 32 bytes; it wraps the managed "
                           "patch signing keys, so restore the original value (never replace it)")
    result = replace_values(text, changes).encode("utf-8")
    env_values(result.decode("utf-8"))
    uid, gid = owner if owner else (None, None)
    changed = not existing or output.read_bytes() != result
    if changed:
        if existing:
            backup = output.with_name(output.name + f".before-install-{time.time_ns()}")
            shutil.copy2(output, backup)
            say(f"Backed up {output} to {backup.name}")
        atomic_write(output, result, 0o640, uid, gid)
    for name in created:
        say(f"Created {name} in {output} (value not shown)")
    if reveal and "DEFAULT_ADMIN_PASSWORD" in created:
        fd = os.open(reveal, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(changes["DEFAULT_ADMIN_PASSWORD"] + "\n")
    for note in notes:
        say("NOTE: " + note)
    if not changed:
        say(f"{output}: unchanged")
    return env_values(result.decode("utf-8"))


def prepare_update_settings(template, output, channel, use_mirror, owner=None, display=None):
    output = Path(output)
    if output.is_symlink():
        raise InstallError(f"refusing the symlink {output}")
    if output.exists():
        say(f"{output}: kept (administrator settings are never replaced)")
        return
    settings = json.loads(Path(template).read_text(encoding="utf-8"))
    settings["channel"] = channel
    settings["use_mirror"] = use_mirror
    uid, gid = owner if owner else (None, None)
    atomic_write(output, (json.dumps(settings, indent=2) + "\n").encode("utf-8"), 0o600, uid, gid)
    say(f"Created {display or output} (channel {channel}, auto_update {str(settings['auto_update']).lower()})")


def wait_healthy(url, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                if response.status == 200 and b'"ok"' in response.read(4096):
                    return True
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(1)
    return False


# ---------------------------------------------------------------------------
# Database (PostgreSQL by default, docs: deploy/linux/README.md "Database")

POSTGRES_DRIVERS = ("postgres", "postgresql", "pg")
DB_NAME = "shorebird"
DB_ROLE = "shorebird"
HBA_BEGIN = "# BEGIN shorebird-server (managed by deploy/linux/install.sh)"
HBA_END = "# END shorebird-server"


def local_database_url(socket_dir, port):
    """Unix-socket URL with peer authentication: no password exists."""
    return (f"postgres:///{DB_NAME}?host={socket_dir}&port={port}&user={DB_ROLE}"
            "&sslmode=disable&connect_timeout=5")


def parse_local_database_url(url):
    """(socket dir, port) when `url` is the installer's local socket URL, else None."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("postgres", "postgresql") or parsed.netloc or parsed.path != f"/{DB_NAME}":
        return None
    query = dict(urllib.parse.parse_qsl(parsed.query))
    host = query.get("host", "")
    if not host.startswith("/") or query.get("user") != DB_ROLE:
        return None
    return host, query.get("port", "5432")


def check_socket_dir(value):
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", value or "") or "/../" in value + "/":
        raise InstallError("--pg-socket expects an absolute directory without spaces")
    return value.rstrip("/") or "/"


def check_port(value):
    if not str(value).isdigit() or not 0 < int(value) < 65536:
        raise InstallError("--pg-port expects 1-65535")
    return str(int(value))


def check_external_url(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("postgres", "postgresql") or any(c.isspace() for c in url) or "'" in url:
        raise InstallError("--database-url expects postgres://USER:PASSWORD@HOST:PORT/DATABASE?sslmode=...")
    return url


def database_plan(env_path, *, sqlite=False, postgres=False, url="", socket_dir="", port=""):
    """(mode, url, socket dir, port): mode is local, external or sqlite.

    A new install uses a local PostgreSQL unless told otherwise. An existing
    install keeps its database; switching between SQLite and PostgreSQL (or to
    another database) is refused, never done silently: it would start an empty
    server next to the old data.
    """
    if sum(map(bool, (sqlite, postgres, url))) > 1:
        raise InstallError("pass only one of --sqlite, --postgres and --database-url")
    explicit_socket = check_socket_dir(socket_dir) if socket_dir else None
    explicit_port = check_port(port) if port else None
    if url:
        check_external_url(url)
        if explicit_socket or explicit_port:
            raise InstallError("--pg-socket/--pg-port select the local PostgreSQL; drop them with --database-url")
    env_path = Path(env_path)
    if not env_path.exists():
        if sqlite:
            return "sqlite", "", "", ""
        if url:
            return "external", url, "", ""
        socket_dir, port = explicit_socket or "/var/run/postgresql", explicit_port or "5432"
        return "local", local_database_url(socket_dir, port), socket_dir, port
    values = env_values(env_path.read_text(encoding="utf-8"))
    driver = (values.get("DB_DRIVER") or "sqlite").lower()
    migrate = "see deploy/linux/README.md, \"Database\""
    if driver in POSTGRES_DRIVERS:
        current = values.get("DATABASE_URL", "")
        if sqlite:
            raise InstallError("this server already uses PostgreSQL (DB_DRIVER in server.env); refusing to switch "
                               f"to SQLite, which would start an empty server ({migrate})")
        local = parse_local_database_url(current)
        if local:
            if url and url != current:
                raise InstallError("this server uses the local PostgreSQL; refusing to switch to --database-url "
                                   f"({migrate})")
            if (explicit_socket and explicit_socket != local[0]) or (explicit_port and explicit_port != local[1]):
                raise InstallError(f"this server uses the local PostgreSQL at {local[0]} port {local[1]}; "
                                   "refusing another --pg-socket/--pg-port")
            return "local", current, local[0], local[1]
        if not current:
            raise InstallError("server.env selects PostgreSQL but has no DATABASE_URL; set it, then rerun")
        if postgres or explicit_socket or explicit_port:
            raise InstallError("this server uses an external PostgreSQL (DATABASE_URL); refusing to switch to a "
                               f"local one ({migrate})")
        if url and url != current:
            raise InstallError("this server already has another DATABASE_URL; edit server.env yourself to move "
                               "it (the installer never replaces it)")
        return "external", current, "", ""
    if driver != "sqlite":
        raise InstallError(f"server.env has an unknown DB_DRIVER {driver!r}")
    if postgres or url or explicit_socket or explicit_port:
        raise InstallError("this server already stores its data in SQLite; switching to PostgreSQL is not "
                           f"automated and would start an empty server ({migrate}). Rerun without "
                           "database options to keep SQLite")
    return "sqlite", "", "", ""


def hba_text(text):
    """pg_hba.conf with exactly one managed peer rule block at the top: the first
    matching rule wins, so a broader password rule cannot shadow it."""
    if HBA_BEGIN in text or HBA_END in text:
        if text.count(HBA_BEGIN) != 1 or text.count(HBA_END) != 1:
            raise InstallError("malformed shorebird-server markers in pg_hba.conf; review it")
        start, end = text.index(HBA_BEGIN), text.index(HBA_END) + len(HBA_END)
        if end <= start:
            raise InstallError("malformed shorebird-server marker order in pg_hba.conf")
        rest = text[end:]
        text = text[:start] + (rest[1:] if rest.startswith("\n") else rest)
    return f"{HBA_BEGIN}\nlocal   {DB_NAME}   {DB_ROLE}   peer\n{HBA_END}\n" + text


def update_hba(path):
    """Prepends the managed rule; returns the backup path ("" when unchanged)."""
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise InstallError(f"{path} is not a regular file")
    original = path.read_text(encoding="utf-8")
    wanted = hba_text(original)
    if wanted == original:
        return ""
    info = path.stat()
    backup = path.with_name(path.name + f".before-shorebird-{time.time_ns()}")
    shutil.copy2(path, backup)
    uid, gid = (info.st_uid, info.st_gid) if os.geteuid() == 0 else (None, None)
    atomic_write(path, wanted.encode("utf-8"), info.st_mode & 0o777, uid, gid)
    return str(backup)


# ---------------------------------------------------------------------------
# Reverse proxy (Caddy, automatic HTTPS)

CADDY_MARK = "# Managed by shorebird-server deploy/linux/install.sh; rerun it to change this file."
STOCK_CADDYFILE = re.compile(r"\A(?:\s*#[^\n]*\n|\s*\n)*:80\s*\{[^{}]*root\s+\*\s+/usr/share/caddy[^{}]*\}\s*"
                             r"(?:#[^\n]*\n?|\s)*\Z")


def check_domain(name):
    if (not re.fullmatch(r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}", name or "")):
        raise InstallError("--domain expects a DNS name such as patch.example.com")
    return name.lower()


def caddy_site(domain, upstream, email):
    lines = [CADDY_MARK, f"{domain} {{"]
    if email:
        lines.append(f"\ttls {email}")
    lines += ["\tencode zstd gzip", f"\treverse_proxy {upstream}", "}"]
    return "\n".join(lines) + "\n"


def write_caddy(domain, upstream, email, caddyfile, site_file, import_path=None):
    """Writes the site file and makes the Caddyfile import it. A stock
    distribution Caddyfile (the :80 welcome page) is replaced, any other one
    gets a single import line; every changed file is backed up first.
    Prints the backups (one per line) for the caller's restore."""
    check_domain(domain)
    if email and not re.fullmatch(r"[^@\s]+@[^@\s]+", email):
        raise InstallError("--acme-email is not an e-mail address")
    caddyfile, site_file = Path(caddyfile), Path(site_file)
    backups = []

    def put(path, text):
        if path.is_symlink():
            raise InstallError(f"refusing the symlink {path}")
        if path.exists():
            if path.read_text(encoding="utf-8") == text:
                return
            backup = path.with_name(path.name + f".before-shorebird-{time.time_ns()}")
            shutil.copy2(path, backup)
            backups.append(str(backup))
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(path, text.encode("utf-8"), 0o644)
    if site_file.exists() and CADDY_MARK not in site_file.read_text(encoding="utf-8"):
        raise InstallError(f"{site_file} was not written by this installer; move it aside first")
    put(site_file, caddy_site(domain, upstream, email))
    line = f"import {import_path or site_file}"
    current = caddyfile.read_text(encoding="utf-8") if caddyfile.exists() else ""
    if not current.strip() or STOCK_CADDYFILE.match(current):
        put(caddyfile, f"{CADDY_MARK}\n{line}\n")
    elif not any(entry.strip() == line for entry in current.splitlines()):
        put(caddyfile, current.rstrip("\n") + f"\n\n# shorebird-server (deploy/linux/install.sh)\n{line}\n")
    return backups


# ---------------------------------------------------------------------------
# Build from source (install.sh --build-from-source)

SOURCE_REPOSITORY = REPOSITORY
PKCS8_ED25519 = bytes.fromhex("302e020100300506032b657004220420")
MAX_SOURCE = 256 << 20
MAX_GO = 512 << 20


def ed25519_public(seed):
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little") & ((1 << 254) - 8) | (1 << 254)
    x, y, z, _ = _mul(scalar, _G)
    inverse = pow(z, _P - 2, _P)
    x, y = x * inverse % _P, y * inverse % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def read_private_key(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise InstallError(f"{path} is not a regular file")
    if path.stat().st_mode & 0o077:
        raise InstallError(f"{path} is readable by group or others; run: chmod 600 {path}")
    lines = path.read_text(encoding="ascii").strip().splitlines()
    if len(lines) < 3 or lines[0] != "-----BEGIN PRIVATE KEY-----" or lines[-1] != "-----END PRIVATE KEY-----":
        raise InstallError(f"{path} is not a PKCS#8 PEM private key")
    try:
        der = base64.b64decode("".join(lines[1:-1]), validate=True)
    except ValueError:
        raise InstallError(f"{path} is not a PKCS#8 PEM private key") from None
    if len(der) != 48 or not der.startswith(PKCS8_ED25519):
        raise InstallError(f"{path} is not an Ed25519 key")
    return der[16:]


def host_key(key_path, trusted_path):
    """The host's update signing key: created once (0600), never replaced. The
    public key is written to `trusted_path` (the pin of every binary built on
    this host). Returns the base64 public key."""
    key_path, trusted_path = Path(key_path), Path(trusted_path)
    if key_path.is_symlink() or trusted_path.is_symlink():
        raise InstallError("refusing a symlinked update key file")
    if not key_path.exists():
        if trusted_path.exists():
            raise InstallError(f"{trusted_path} exists without {key_path}; restore the key from your backup "
                               "(binaries built here trust only that key), or move both aside for a new install")
        seed = secrets.token_bytes(32)
        pem = ("-----BEGIN PRIVATE KEY-----\n" + base64.b64encode(PKCS8_ED25519 + seed).decode("ascii")
               + "\n-----END PRIVATE KEY-----\n")
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(pem)
            stream.flush()
            os.fsync(stream.fileno())
        say(f"Created the host update signing key {key_path} (0600; back it up)")
    public = base64.b64encode(ed25519_public(read_private_key(key_path))).decode("ascii")
    text = ("# shorebird-server update key of this host (public). install.sh --build-from-source pins it\n"
            f"# into every binary it builds; the private key is {key_path}.\n{public}\n")
    if trusted_path.exists():
        pinned = [line.split("#", 1)[0].strip() for line in trusted_path.read_text(encoding="ascii").splitlines()]
        if [entry for entry in pinned if entry] != [public]:
            raise InstallError(f"{trusted_path} does not hold the public key of {key_path}; restore the pair")
    else:
        atomic_write(trusted_path, text.encode("ascii"), 0o644)
    return public


def go_version(go_mod):
    """The toolchain go.mod asks for (`toolchain goX`, else `go X`)."""
    text = Path(go_mod).read_text(encoding="utf-8")
    toolchain = re.search(r"^toolchain\s+(go[0-9][0-9A-Za-z.]*)\s*$", text, re.M)
    if toolchain:
        return toolchain.group(1)
    language = re.search(r"^go\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s*$", text, re.M)
    if not language:
        raise InstallError(f"{go_mod} names no Go version")
    return "go" + language.group(1)


def safe_extract(archive_path, destination, *, strip_root=False, limit=MAX_GO * 4):
    """Extracts a tar.gz without links, devices or paths leaving `destination`
    (Python 3.8 has no tar filters). Symbolic and hard links are skipped (the
    sources and the Go distribution build without them). Returns (top-level
    directory, skipped links)."""
    import tarfile
    destination = Path(destination)
    destination.mkdir(parents=True)
    total = 0
    skipped = 0
    root = None
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive:
            name = member.name
            parts = Path(name).parts
            if name.startswith("/") or ".." in parts or not parts:
                raise InstallError(f"unsafe archive entry {name!r}")
            if root is None:
                root = parts[0]
            if parts[0] != root:
                raise InstallError("the archive has more than one top-level directory")
            if strip_root:
                parts = parts[1:]
                if not parts:
                    continue
            target = destination.joinpath(*parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                total += member.size
                if total > limit:
                    raise InstallError("the archive is too large")
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source, open(target, "xb") as output:
                    shutil.copyfileobj(source, output)
                os.chmod(target, 0o755 if member.mode & 0o111 else 0o644)
            elif member.issym() or member.islnk():
                skipped += 1
            elif member.type == tarfile.XGLTYPE or member.type == tarfile.XHDTYPE:
                continue
            else:
                raise InstallError(f"unsupported archive entry {name!r}")
    return root, skipped


def go_toolchain(version, directory, platform, opener=None):
    """GOROOT of `version` under `directory`: downloaded from go.dev, verified
    against go.dev's published SHA-256, extracted once and reused."""
    if not re.fullmatch(r"go[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:(?:rc|beta)[0-9]+)?", version):
        raise InstallError(f"invalid Go version {version!r}")
    goos, goarch = platform.split("-")
    directory = Path(directory)
    goroot = directory / version / "go"
    marker = directory / version / ".verified"
    with tempfile.TemporaryDirectory(prefix=".go-", dir=str(directory)) as temporary:
        temporary = Path(temporary)
        download("https://go.dev/dl/?mode=json&include=all", temporary / "index.json", 16 << 20, False, opener,
                 hosts=GO_HOSTS)
        try:
            index = json.loads((temporary / "index.json").read_bytes())
        except ValueError:
            raise InstallError("the go.dev release index is not JSON") from None
        wanted = None
        for release in index if isinstance(index, list) else []:
            if not isinstance(release, dict) or release.get("version") != version:
                continue
            for item in release.get("files", []):
                if (isinstance(item, dict) and item.get("os") == goos and item.get("arch") == goarch
                        and item.get("kind") == "archive"):
                    wanted = item
        if (wanted is None or not re.fullmatch(r"[0-9a-f]{64}", str(wanted.get("sha256", "")))
                or wanted.get("filename") != f"{version}.{goos}-{goarch}.tar.gz"):
            raise InstallError(f"go.dev publishes no {version} archive for {platform}")
        if marker.is_file() and marker.read_text(encoding="ascii").strip() == wanted["sha256"] and \
                (goroot / "bin" / "go").is_file():
            return goroot
        if (directory / version).exists():
            shutil.rmtree(directory / version)
        say(f"Downloading {wanted['filename']} from go.dev...")
        archive = temporary / "go.tar.gz"
        download(f"https://dl.google.com/go/{wanted['filename']}", archive, MAX_GO, False, opener,
                 hosts=GO_HOSTS, seconds=1800)
        digest = hashlib.sha256()
        with open(archive, "rb") as stream:
            for block in iter(lambda: stream.read(1 << 20), b""):
                digest.update(block)
        if digest.hexdigest() != wanted["sha256"]:
            raise InstallError(f"{wanted['filename']} does not match the SHA-256 go.dev publishes")
        staged = temporary / "root"
        root, _ = safe_extract(archive, staged)
        if root != "go" or not (staged / "go" / "bin" / "go").is_file():
            raise InstallError("unexpected Go archive layout")
        (directory / version).mkdir()
        (staged / "go").replace(goroot)
        marker.write_text(wanted["sha256"] + "\n", encoding="ascii")
    return goroot


def resolve_ref(ref, opener=None, repository=SOURCE_REPOSITORY):
    """(commit SHA, commit UTC epoch) of `ref` on GitHub."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}", ref) or ".." in ref:
        raise InstallError(f"invalid --ref {ref!r}")
    with tempfile.TemporaryDirectory(prefix="shorebird-ref-") as temporary:
        path = Path(temporary) / "commit.json"
        download(f"https://api.github.com/repos/{repository}/commits/{urllib.parse.quote(ref, safe='')}", path,
                 1 << 20, False, opener, hosts=GITHUB_HOSTS, accept="application/vnd.github+json")
        try:
            commit = json.loads(path.read_bytes())
            sha = commit["sha"]
            when = commit["commit"]["committer"]["date"]
        except (ValueError, KeyError, TypeError):
            raise InstallError(f"GitHub returned no commit for {ref!r}") from None
    if not re.fullmatch(r"[0-9a-f]{40}", str(sha)):
        raise InstallError("GitHub returned an invalid commit")
    epoch = int(datetime_epoch(when))
    return sha, epoch


def datetime_epoch(text):
    import datetime
    try:
        moment = datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except (TypeError, ValueError):
        raise InstallError("GitHub returned an invalid commit date") from None
    return moment.timestamp()


def fetch_source(sha, destination, opener=None, repository=SOURCE_REPOSITORY):
    """Extracts the source tree of commit `sha` into `destination` (TLS-authenticated
    GitHub archive of an immutable commit)."""
    with tempfile.TemporaryDirectory(prefix="shorebird-src-") as temporary:
        archive = Path(temporary) / "source.tar.gz"
        say(f"Downloading the source of {repository}@{sha[:12]}...")
        download(f"https://codeload.github.com/{repository}/tar.gz/{sha}", archive, MAX_SOURCE, False, opener,
                 hosts=GITHUB_HOSTS, seconds=900)
        safe_extract(archive, destination, strip_root=True, limit=MAX_SOURCE * 4)
    check_source(destination)


def check_source(directory):
    directory = Path(directory)
    for required in ("go.mod", "cmd/server", "cmd/server-update-tool", "VERSION"):
        if not (directory / required).exists():
            raise InstallError(f"{directory} is not a shorebird-server source tree (no {required})")


def source_version(source, sha, epoch, ref="", installed=""):
    """The version a host build gets.

    A release tag (`--ref v1.2.3`) builds exactly that stable version. Anything
    else is a dev build `vX.Y.Z-dev.<commit UTC time>.g<commit12>` where X.Y.Z is
    the next patch after the source's VERSION and after the installed stable
    version (an installed dev version keeps its X.Y.Z), so later commits sort
    later and the server's self-update accepts them as newer.
    """
    import datetime
    if VERSION.fullmatch(ref or "") and "-" not in ref:
        return ref
    base = (Path(source) / "VERSION").read_text(encoding="ascii").strip()
    match = re.fullmatch(r"v([0-9]+)\.([0-9]+)\.([0-9]+)", base)
    if not match:
        raise InstallError("the source VERSION is not vMAJOR.MINOR.PATCH")
    core = (int(match.group(1)), int(match.group(2)), int(match.group(3)) + 1)
    installed_match = VERSION.fullmatch(installed or "")
    if installed_match:
        major, minor, patch, pre = installed_match.groups()
        floor = (int(major), int(minor), int(patch) + (0 if pre else 1))
        core = max(core, floor)
    when = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    return f"v{core[0]}.{core[1]}.{core[2]}-dev.{when:%Y%m%d%H%M%S}.g{sha[:12]}"


MODULE = "github.com/shorebird-server"


def build_ldflags(version, build_time, trusted):
    """Same link flags as scripts/build_update_zip.py (a test keeps them equal)."""
    return ["-s", "-w", f"-X {MODULE}/internal/version.Version={version}",
            f"-X {MODULE}/internal/version.BuildTime={build_time}",
            f"-X {MODULE}/internal/updater.TrustedKeys={trusted}"]


def build_from_source(source, goroot, work, key, trusted, platform, version, epoch, output, expected_go=""):
    """Builds, signs (production, host key) and zips one update; returns the ZIP."""
    import datetime
    source, goroot, work, output = Path(source), Path(goroot), Path(work), Path(output)
    goos, goarch = platform.split("-")
    go = goroot / "bin" / "go"
    for name in ("gopath", "gocache", "home"):
        (work / name).mkdir(parents=True, exist_ok=True)
    shutil.rmtree(work / "out", ignore_errors=True)
    (work / "out").mkdir()
    environment = {
        "PATH": f"{goroot / 'bin'}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": str(work / "home"), "GOROOT": str(goroot), "GOPATH": str(work / "gopath"),
        "GOMODCACHE": str(work / "gopath" / "pkg" / "mod"), "GOCACHE": str(work / "gocache"),
        "GOTOOLCHAIN": "local", "GOFLAGS": "-mod=readonly", "GOENV": "off", "CGO_ENABLED": "0",
        "LANG": "C.UTF-8",
    }
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy", "GOPROXY",
                 "GOSUMDB", "GOPRIVATE", "SSL_CERT_FILE", "SSL_CERT_DIR"):
        if name in os.environ:
            environment[name] = os.environ[name]
    reported = subprocess.run([str(go), "env", "GOVERSION"], env=environment, capture_output=True, text=True)
    if reported.returncode != 0:
        raise InstallError(f"the Go toolchain does not run: {reported.stderr.strip()}")
    if expected_go and reported.stdout.strip() != expected_go:
        raise InstallError(f"the toolchain reports {reported.stdout.strip()}, go.mod asks for {expected_go}")
    tool = work / "server-update-tool"
    say(f"Building shorebird-server {version} for {platform} (Go {reported.stdout.strip()})...")
    run = lambda arguments, env: subprocess.run(arguments, cwd=str(source), env=env, check=True)  # noqa: E731
    try:
        run([str(go), "build", "-trimpath", "-o", str(tool), "./cmd/server-update-tool"], environment)
        release = work / "out"
        asset = f"{PRODUCT}-{platform}"
        binary = release / asset
        when = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        public = host_trusted_list(trusted)
        run([str(go), "build", "-trimpath", "-ldflags=" + " ".join(build_ldflags(version, when, public)), "-o",
             str(binary), "./cmd/server"], dict(environment, GOOS=goos, GOARCH=goarch))
        subprocess.run([str(tool), "sign", "-key", str(key), "-binary", str(binary), "-version", version, "-goos", goos,
                        "-goarch", goarch, "-out-dir", str(release), "-trusted", public, "-production"],
                       env=environment, check=True, stdout=subprocess.DEVNULL)
    except subprocess.CalledProcessError as error:
        raise InstallError(f"the build failed ({' '.join(error.cmd[:3])}...); see the output above") from None
    (release / "VERSION").write_text(version + "\n", encoding="ascii")
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in (asset, asset + ".manifest.json", asset + ".sig", "VERSION"):
            archive.write(release / name, name)
    return output


def host_trusted_list(path):
    entries = [line.split("#", 1)[0].strip() for line in Path(path).read_text(encoding="ascii").splitlines()]
    entries = [entry for entry in entries if entry]
    if not entries:
        raise InstallError(f"{path} pins no key")
    return ",".join(entries)


# ---------------------------------------------------------------------------
# Local upgrade through the running server's self-update transaction


def _local_request(url, secret_file, data=None, timeout=30):
    secret = Path(secret_file).read_text(encoding="ascii").strip()
    headers = {"Authorization": f"Bearer {secret}", "User-Agent": "shorebird-server-installer"}
    if data is not None:
        headers["Content-Type"] = "application/zip"
    request = urllib.request.Request(url, data=data, headers=headers, method="POST" if data is not None else "GET")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, json.loads(response.read(1 << 20) or b"{}")
    except urllib.error.HTTPError as error:
        try:
            body = json.loads(error.read(1 << 16) or b"{}")
        except ValueError:
            body = {}
        return error.code, body


def local_update(zip_path, base, bin_dir, version, seconds=600, interval=1.0):
    """Hands a verified update ZIP to the running server (local upload route, or
    the maintenance route when the core is in maintenance) and waits until the
    new version runs: the server's own transaction installs it on trial with
    watchdog rollback and quarantine. Returns the final status."""
    local_secret = Path(bin_dir) / "server-local-update.secret"
    maintenance_secret = Path(bin_dir) / "server-maintenance.secret"
    data = Path(zip_path).read_bytes()
    if local_secret.is_file():
        status, body = _local_request(base + "/api/v1/server/update/local", local_secret, data, timeout=900)
    elif maintenance_secret.is_file():
        say("The server is in maintenance; delivering the update through the maintenance route.")
        status, body = _local_request(base + "/api/v1/server/maintenance/update", maintenance_secret, data,
                                      timeout=900)
    else:
        raise InstallError(f"no {local_secret.name} in {bin_dir}: the running server cannot take a local update "
                           "(not running, self-update not active, or an older version without the local route). "
                           "Upload the ZIP as an administrator instead (docs/SELF_UPDATE.md)")
    if status != 202:
        raise InstallError(f"the server refused the update: {body.get('code') or status}")
    say(f"The server accepted {version}; waiting for the restart and its trial...")
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        time.sleep(interval)
        try:
            if not local_secret.is_file():
                continue
            status, body = _local_request(base + "/api/v1/server/update/local", local_secret, timeout=5)
        except (OSError, urllib.error.URLError, ValueError):
            continue
        if status != 200:
            continue
        last = body
        if body.get("rolled_back_version") == version:
            raise InstallError(f"{version} failed its trial and was rolled back (quarantined); "
                               "see journalctl -u shorebird-server")
        if body.get("current_version") == version and body.get("journal_state") in ("trial", "healthy"):
            return body
        if body.get("state") == "error":
            raise InstallError(f"the update failed: {body.get('error_code')}")
    raise InstallError(f"{version} did not start within {seconds} s (last status: "
                       f"{(last or {}).get('current_version')}, {(last or {}).get('state')})")


# ---------------------------------------------------------------------------
# CLI used by install_body.sh


def _owner(value):
    if not value:
        return None
    uid, gid = value.split(":")
    return int(uid), int(gid)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    trust = argparse.ArgumentParser(add_help=False)
    trust.add_argument("--trusted-keys-file", required=True)
    trust.add_argument("--allow-development", action="store_true")
    trust.add_argument("--platform", required=True, choices=PLATFORMS + ("darwin-arm64", "darwin-amd64"))
    trust.add_argument("--output", required=True)
    fetch = sub.add_parser("download", parents=[trust])
    fetch.add_argument("--channel", choices=("auto", "stable", "dev"), default="auto")
    fetch.add_argument("--use-mirror", action="store_true")
    files = sub.add_parser("verify", parents=[trust])
    files.add_argument("--binary", required=True)
    files.add_argument("--manifest", required=True)
    files.add_argument("--signature", required=True)
    archive = sub.add_parser("verify-zip", parents=[trust])
    archive.add_argument("--zip", required=True)
    env = sub.add_parser("environment")
    env.add_argument("--template", required=True)
    env.add_argument("--output", required=True)
    env.add_argument("--state-dir", required=True)
    env.add_argument("--base-url", default="")
    env.add_argument("--listen", default="")
    env.add_argument("--admin-email", default="")
    env.add_argument("--owner", default="")
    env.add_argument("--print-port", action="store_true")
    settings = sub.add_parser("update-settings")
    settings.add_argument("--template", required=True)
    settings.add_argument("--output", required=True)
    settings.add_argument("--channel", choices=("stable", "dev"), required=True)
    settings.add_argument("--use-mirror", choices=("true", "false"), default="false")
    settings.add_argument("--owner", default="")
    settings.add_argument("--display", default="", help="the final path, for the message")
    env.add_argument("--default-listen", default="")
    env.add_argument("--db-driver", choices=("", "sqlite", "postgres"), default="")
    env.add_argument("--db-url", default="")
    env.add_argument("--reveal", default="", help="file for a generated administrator password (0600)")
    plan = sub.add_parser("database-plan", help="print: MODE URL SOCKET PORT (refuses database switches)")
    plan.add_argument("--env", required=True)
    plan.add_argument("--sqlite", action="store_true")
    plan.add_argument("--postgres", action="store_true")
    plan.add_argument("--database-url", default="")
    plan.add_argument("--pg-socket", default="")
    plan.add_argument("--pg-port", default="")
    hba = sub.add_parser("hba", help="prepend the managed peer rule; print the backup path")
    hba.add_argument("--output", required=True)
    caddy = sub.add_parser("caddy", help="write the Caddy site; print the backups")
    caddy.add_argument("--domain", required=True)
    caddy.add_argument("--upstream", required=True)
    caddy.add_argument("--acme-email", default="")
    caddy.add_argument("--caddyfile", required=True)
    caddy.add_argument("--site-file", required=True)
    caddy.add_argument("--import-path", default="", help="the site file's path as Caddy sees it")
    compare = sub.add_parser("compare", help="print -1, 0 or 1 (semantic version order)")
    compare.add_argument("left")
    compare.add_argument("right")
    domain = sub.add_parser("check-domain")
    domain.add_argument("--domain", required=True)
    key = sub.add_parser("host-key", help="create the host update key once; print its public key")
    key.add_argument("--key", required=True)
    key.add_argument("--trusted", required=True)
    toolchain = sub.add_parser("go-toolchain", help="print GOROOT of the go.mod toolchain (downloaded, verified)")
    toolchain.add_argument("--go-mod", required=True)
    toolchain.add_argument("--dir", required=True)
    toolchain.add_argument("--platform", required=True, choices=PLATFORMS)
    gover = sub.add_parser("go-version")
    gover.add_argument("--go-mod", required=True)
    ref = sub.add_parser("resolve-ref", help="print: SHA EPOCH")
    ref.add_argument("--ref", required=True)
    fetch_src = sub.add_parser("fetch-source")
    fetch_src.add_argument("--sha", required=True)
    fetch_src.add_argument("--dir", required=True)
    srcver = sub.add_parser("source-version")
    srcver.add_argument("--source", required=True)
    srcver.add_argument("--sha", required=True)
    srcver.add_argument("--epoch", type=int, required=True)
    srcver.add_argument("--ref", default="")
    srcver.add_argument("--installed", default="")
    build = sub.add_parser("build", help="build, sign and zip one update from source")
    build.add_argument("--source", required=True)
    build.add_argument("--goroot", required=True)
    build.add_argument("--expected-go", default="")
    build.add_argument("--work", required=True)
    build.add_argument("--key", required=True)
    build.add_argument("--trusted", required=True)
    build.add_argument("--platform", required=True, choices=PLATFORMS)
    build.add_argument("--version", required=True)
    build.add_argument("--epoch", type=int, required=True)
    build.add_argument("--output", required=True)
    upgrade = sub.add_parser("local-update", help="install a verified ZIP through the running server")
    upgrade.add_argument("--zip", required=True)
    upgrade.add_argument("--url", required=True)
    upgrade.add_argument("--bin-dir", required=True)
    upgrade.add_argument("--version", required=True)
    upgrade.add_argument("--seconds", type=int, default=600)
    health = sub.add_parser("health")
    health.add_argument("--url", required=True)
    health.add_argument("--seconds", type=int, default=120)
    args = parser.parse_args(argv)
    try:
        if args.command in ("download", "verify", "verify-zip"):
            trusted = load_trusted_keys(args.trusted_keys_file, args.allow_development)
            if args.command == "download":
                manifest = download_release(args.output, args.platform, args.channel, args.use_mirror, trusted)
            elif args.command == "verify":
                manifest = verify_files(args.binary, args.manifest, args.signature, args.platform, trusted, args.output)
            else:
                manifest = verify_zip(args.zip, args.platform, trusted, args.output)
            # stdout: "<version> <channel>" for install_body.sh
            print(manifest["version"], manifest["channel"])
        elif args.command == "environment":
            values = prepare_environment(args.template, args.output, args.state_dir, base=args.base_url or None,
                                         listen=args.listen or None, admin_email=args.admin_email or None,
                                         owner=_owner(args.owner), default_listen=args.default_listen or None,
                                         db_driver=args.db_driver or None, db_url=args.db_url or None,
                                         reveal=args.reveal or None)
            if args.print_port:
                print(f"PORT={values.get('SERVER_PORT', '8080')}")
        elif args.command == "update-settings":
            prepare_update_settings(args.template, args.output, args.channel, args.use_mirror == "true",
                                    _owner(args.owner), args.display or None)
        elif args.command == "database-plan":
            print(" ".join(item or "-" for item in database_plan(
                args.env, sqlite=args.sqlite, postgres=args.postgres, url=args.database_url,
                socket_dir=args.pg_socket, port=args.pg_port)))
        elif args.command == "hba":
            print(update_hba(args.output))
        elif args.command == "caddy":
            for backup in write_caddy(args.domain, args.upstream, args.acme_email, args.caddyfile, args.site_file,
                                      args.import_path or None):
                print(backup)
        elif args.command == "compare":
            try:
                left, right = version_key(args.left), version_key(args.right)
            except ValueError:
                raise InstallError("invalid version") from None
            print((left > right) - (left < right))
        elif args.command == "check-domain":
            print(check_domain(args.domain))
        elif args.command == "host-key":
            print(host_key(args.key, args.trusted))
        elif args.command == "go-version":
            print(go_version(args.go_mod))
        elif args.command == "go-toolchain":
            print(go_toolchain(go_version(args.go_mod), args.dir, args.platform))
        elif args.command == "resolve-ref":
            print(*resolve_ref(args.ref))
        elif args.command == "fetch-source":
            fetch_source(args.sha, args.dir)
        elif args.command == "source-version":
            print(source_version(args.source, args.sha, args.epoch, args.ref, args.installed))
        elif args.command == "build":
            build_from_source(args.source, args.goroot, args.work, args.key, args.trusted, args.platform,
                              args.version, args.epoch, args.output, args.expected_go)
        elif args.command == "local-update":
            status = local_update(args.zip, args.url, args.bin_dir, args.version, args.seconds)
            print(status.get("current_version", ""), status.get("journal_state", ""))
        else:
            return 0 if wait_healthy(args.url, args.seconds) else 1
    except (InstallError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
