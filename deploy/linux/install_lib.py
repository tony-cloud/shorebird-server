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


def allowed_url(url):
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or ""
    return (parsed.scheme == "https" and parsed.username is None and parsed.password is None
            and (host in ("github.com", "api.github.com", urllib.parse.urlsplit(MIRROR).hostname)
                 or host.endswith(".githubusercontent.com")))


class _Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        if not allowed_url(new_url):
            raise InstallError("release redirect refused")
        return super().redirect_request(request, fp, code, message, headers, new_url)


def download(url, destination, limit, use_mirror, opener=None):
    if not allowed_url(url):
        raise InstallError("release URL refused")
    mirrored = MIRROR + url[len("https://"):]
    targets = [mirrored, url] if use_mirror else [url, mirrored]
    opener = opener or urllib.request.build_opener(_Redirects())
    last = None
    for target in targets:
        try:
            request = urllib.request.Request(target, headers={"User-Agent": "shorebird-server-installer"})
            deadline = time.monotonic() + 300
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
    raise InstallError(f"download failed through GitHub and the mirror: {last}")


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


def prepare_environment(template, output, state_dir, *, base=None, listen=None, admin_email=None, owner=None):
    """Creates missing secrets and settings; existing values are never replaced."""
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
        host, port = listen_address(listen or "0.0.0.0:8080")
        changes.update(SERVER_HOST=host, SERVER_PORT=port)
    port = changes.get("SERVER_PORT") or values.get("SERVER_PORT") or "8080"
    if not existing or base:
        changes["SERVER_BASE_URL"] = base_url(base or f"http://{socket.getfqdn() or 'localhost'}:{port}")
    if admin_email:
        if not re.fullmatch(r"[^@\s]+@[^@\s]+", admin_email):
            raise InstallError("--admin-email is not an e-mail address")
        changes["DEFAULT_ADMIN_EMAIL"] = admin_email
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
                                         owner=_owner(args.owner))
            if args.print_port:
                print(f"PORT={values.get('SERVER_PORT', '8080')}")
        elif args.command == "update-settings":
            prepare_update_settings(args.template, args.output, args.channel, args.use_mirror == "true",
                                    _owner(args.owner), args.display or None)
        else:
            return 0 if wait_healthy(args.url, args.seconds) else 1
    except (InstallError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
