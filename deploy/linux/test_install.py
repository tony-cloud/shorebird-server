#!/usr/bin/env python3
"""Tests for the one-shot Linux installer (deploy/linux).

Everything runs unprivileged: the shell installer is exercised in --root
staging mode in a temporary prefix (no user, ownership or systemd changes),
with a fake server binary signed by the public DEVELOPMENT-ONLY key.
"""
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import threading
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = Path(__file__).resolve().parent
SERVER = HERE.parents[1]
sys.path.insert(0, str(HERE))
import build_installer  # noqa: E402
import install_lib as lib  # noqa: E402

DEV_PEM = SERVER / "signing" / "server-update.DEVELOPMENT-ONLY.pem"
PLATFORM = "linux-amd64"
ASSET = "shorebird-server-linux-amd64"


def pem_seed(path):
    body = "".join(line for line in Path(path).read_text().splitlines() if "-----" not in line)
    der = base64.b64decode(body)
    assert der.startswith(bytes.fromhex("302e020100300506032b657004220420")) and len(der) == 48
    return der[16:]


def sign(seed, message):
    """RFC 8032 signing on install_lib's curve operations (tests only)."""
    digest = hashlib.sha512(seed).digest()
    a = int.from_bytes(digest[:32], "little") & ((1 << 254) - 8) | (1 << 254)

    def compress(point):
        zinv = pow(point[2], lib._P - 2, lib._P)
        x, y = point[0] * zinv % lib._P, point[1] * zinv % lib._P
        return int.to_bytes(y | ((x & 1) << 255), 32, "little")
    public = compress(lib._mul(a, lib._G))
    r = int.from_bytes(hashlib.sha512(digest[32:] + message).digest(), "little") % lib._L
    encoded_r = compress(lib._mul(r, lib._G))
    h = int.from_bytes(hashlib.sha512(encoded_r + public + message).digest(), "little") % lib._L
    return public, encoded_r + int.to_bytes((r + h * a) % lib._L, 32, "little")


DEV_SEED = pem_seed(DEV_PEM)
OTHER_SEED = bytes(range(32))


def manifest_bytes(binary, version, channel=None, platform=PLATFORM, **override):
    goos, goarch = platform.split("-")
    fields = {"product": "shorebird-server", "version": version,
              "channel": channel or ("dev" if "-" in version else "stable"),
              "goos": goos, "goarch": goarch, "asset": f"shorebird-server-{platform}",
              "sha256": hashlib.sha256(binary).hexdigest(), "size": len(binary)}
    fields.update(override)
    # Same bytes as Go's json.Marshal of updater.Manifest.
    return json.dumps(fields, separators=(",", ":")).encode()


def signature_bytes(manifest, seed=DEV_SEED):
    public, raw = sign(seed, lib.SIGNATURE_DOMAIN + hashlib.sha256(manifest).hexdigest().encode())
    return json.dumps({"key_id": lib.key_id(public), "signature": base64.b64encode(raw).decode()},
                      separators=(",", ":")).encode()


def fake_binary(version):
    return f'#!/bin/sh\nif [ "$1" = --version ]; then echo {version}; exit 0; fi\nexit 3\n'.encode()


def write_release(directory, version, *, seed=DEV_SEED, binary=None):
    directory.mkdir(parents=True, exist_ok=True)
    data = binary if binary is not None else fake_binary(version)
    path = directory / ASSET
    path.write_bytes(data)
    path.chmod(0o755)
    manifest = manifest_bytes(data, version)
    (directory / (ASSET + ".manifest.json")).write_bytes(manifest)
    (directory / (ASSET + ".sig")).write_bytes(signature_bytes(manifest, seed))
    (directory / "VERSION").write_text(version + "\n")
    return path


def dev_trust():
    with tempfile.NamedTemporaryFile("w", suffix=".keys", delete=False) as empty:
        empty.write("# no production key\n")
    try:
        return lib.load_trusted_keys(empty.name, True)
    finally:
        os.unlink(empty.name)


class BundleTest(unittest.TestCase):
    def test_install_sh_is_current(self):
        self.assertEqual((HERE / "install.sh").read_bytes(), build_installer.render(),
                         "run deploy/linux/build_installer.py")

    def test_shell_syntax(self):
        for name in ("install.sh", "install_body.sh", "install_dependencies.sh"):
            subprocess.run(["bash", "-n", str(HERE / name)], check=True)

    @unittest.skipUnless(shutil.which("shellcheck"), "shellcheck is not installed")
    def test_shellcheck(self):
        subprocess.run(["shellcheck", str(HERE / "install_body.sh"), str(HERE / "install_dependencies.sh")],
                       check=True)

    def test_bundle_has_no_private_material(self):
        text = (HERE / "install.sh").read_text()
        # The installer creates keys at run time; it carries none (no PEM body, no seed).
        self.assertNotRegex(text, r"-----BEGIN [A-Z ]*PRIVATE KEY-----\s*\n\s*[A-Za-z0-9+/=]{40}")
        self.assertNotIn(base64.b64encode(DEV_SEED).decode(), text)
        committed = (SERVER / "signing" / "server-update.trusted-keys").read_text()
        self.assertIn(committed.rstrip(), text)


class TrustTest(unittest.TestCase):
    def keys_file(self, text):
        handle = tempfile.NamedTemporaryFile("w", delete=False)
        handle.write(text)
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def test_empty_pin_refuses_without_development(self):
        with self.assertRaisesRegex(lib.InstallError, "pins no production update key"):
            lib.load_trusted_keys(self.keys_file("# nothing\n"), False)

    def test_development_key_refused_unless_allowed(self):
        path = self.keys_file(lib.DEVELOPMENT_PUBLIC_KEY + "\n")
        with self.assertRaisesRegex(lib.InstallError, "DEVELOPMENT-ONLY"):
            lib.load_trusted_keys(path, False)
        self.assertEqual(len(lib.load_trusted_keys(path, True)), 1)

    def test_production_keys_parse(self):
        public, _ = sign(OTHER_SEED, b"x")
        keys = lib.load_trusted_keys(self.keys_file(f"# pinned\n{base64.b64encode(public).decode()}\n"), False)
        self.assertEqual(list(keys), [lib.key_id(public)])

    def test_malformed_and_duplicate_keys(self):
        public, _ = sign(OTHER_SEED, b"x")
        encoded = base64.b64encode(public).decode()
        for text in ("not-base64!\n", encoded[:-2] + "\n", f"{encoded}\n{encoded}\n"):
            with self.assertRaises(lib.InstallError):
                lib.load_trusted_keys(self.keys_file(text), False)


class ManifestTest(unittest.TestCase):
    def setUp(self):
        self.trust = dev_trust()
        self.binary = fake_binary("v1.2.3")
        self.manifest = manifest_bytes(self.binary, "v1.2.3")

    def test_valid_manifest(self):
        m = lib.verify_manifest(self.manifest, signature_bytes(self.manifest), PLATFORM, self.trust)
        self.assertEqual((m["version"], m["channel"]), ("v1.2.3", "stable"))

    def test_signature_is_checked_before_fields(self):
        tampered = self.manifest.replace(b"v1.2.3", b"v1.2.4")
        with self.assertRaisesRegex(lib.InstallError, "signature_invalid"):
            lib.verify_manifest(tampered, signature_bytes(self.manifest), PLATFORM, self.trust)

    def test_untrusted_signer(self):
        with self.assertRaisesRegex(lib.InstallError, "untrusted_signer"):
            lib.verify_manifest(self.manifest, signature_bytes(self.manifest, OTHER_SEED), PLATFORM, self.trust)

    def test_wrong_platform(self):
        with self.assertRaisesRegex(lib.InstallError, "wrong_platform"):
            lib.verify_manifest(self.manifest, signature_bytes(self.manifest), "linux-arm64", self.trust)

    def test_invalid_fields(self):
        cases = [
            manifest_bytes(self.binary, "v1.2.3-dev.1", channel="stable"),
            manifest_bytes(self.binary, "v1.2.3", channel="dev"),
            manifest_bytes(self.binary, "v1.2.3", product="other"),
            manifest_bytes(self.binary, "1.2.3"),
            manifest_bytes(self.binary, "v1.2.3", sha256="AB" * 32),
            manifest_bytes(self.binary, "v1.2.3", size=0),
            manifest_bytes(self.binary, "v1.2.3", extra=1),
        ]
        for manifest in cases:
            with self.subTest(manifest=manifest), self.assertRaises(lib.InstallError):
                lib.verify_manifest(manifest, signature_bytes(manifest), PLATFORM, self.trust)

    def test_malformed_signature_files(self):
        good = json.loads(signature_bytes(self.manifest))
        for document in ({"key_id": good["key_id"]}, dict(good, extra=1),
                         dict(good, signature=good["signature"].rstrip("=")),
                         dict(good, signature=base64.b64encode(b"x" * 63).decode())):
            with self.subTest(document=document), self.assertRaises(lib.InstallError):
                lib.verify_manifest(self.manifest, json.dumps(document).encode(), PLATFORM, self.trust)

    def test_checksum(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "b"
            path.write_bytes(self.binary + b"\n")
            m = lib.verify_manifest(self.manifest, signature_bytes(self.manifest), PLATFORM, self.trust)
            with self.assertRaisesRegex(lib.InstallError, "checksum_mismatch"):
                lib.check_binary(path, m)


class ZipTest(unittest.TestCase):
    def setUp(self):
        self.trust = dev_trust()
        self.directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.directory)
        self.release = write_release(self.directory / "release", "v2.0.0").parent

    def make_zip(self, names=None, version_text=None):
        path = self.directory / "update.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for name in names or (ASSET, ASSET + ".manifest.json", ASSET + ".sig", "VERSION"):
                if name == "VERSION" and version_text is not None:
                    archive.writestr(name, version_text)
                elif (self.release / name).exists():
                    archive.write(self.release / name, name)
                else:
                    archive.writestr(name, b"extra")
        return path

    def test_valid_zip(self):
        output = self.directory / "out"
        m = lib.verify_zip(self.make_zip(), PLATFORM, self.trust, output)
        self.assertEqual(m["version"], "v2.0.0")
        self.assertEqual(output.read_bytes(), (self.release / ASSET).read_bytes())

    def test_layout_and_version_refusals(self):
        for path in (self.make_zip(names=(ASSET, ASSET + ".manifest.json", ASSET + ".sig", "VERSION", "x")),
                     self.make_zip(names=(ASSET, ASSET + ".manifest.json", ASSET + ".sig")),
                     self.make_zip(version_text="v9.9.9\n")):
            with self.subTest(path=path), self.assertRaises(lib.InstallError):
                lib.verify_zip(path, PLATFORM, self.trust, self.directory / "out")


class ReleaseSelectionTest(unittest.TestCase):
    @staticmethod
    def release(tag, prerelease=False, draft=False, assets=(ASSET, ASSET + ".manifest.json", ASSET + ".sig")):
        return {"tag_name": tag, "prerelease": prerelease, "draft": draft,
                "assets": [{"name": name, "state": "uploaded"} for name in assets]}

    def test_auto_prefers_stable_then_dev(self):
        releases = [self.release("v1.0.0"), self.release("v1.1.0-dev.2", True), self.release("v0.9.0")]
        self.assertEqual(lib.select_release(releases, "auto", ASSET)["tag_name"], "v1.0.0")
        self.assertEqual(lib.select_release(releases, "dev", ASSET)["tag_name"], "v1.1.0-dev.2")
        only_dev = [self.release("v1.1.0-dev.2", True), self.release("v1.1.0-dev.10", True)]
        self.assertEqual(lib.select_release(only_dev, "auto", ASSET)["tag_name"], "v1.1.0-dev.10")
        with self.assertRaises(lib.InstallError):
            lib.select_release(only_dev, "stable", ASSET)

    def test_incomplete_draft_and_invalid_releases_are_skipped(self):
        releases = [self.release("v3.0.0", assets=(ASSET, ASSET + ".sig")), self.release("v2.0.0", draft=True),
                    self.release("latest"), self.release("v1.0.0")]
        self.assertEqual(lib.select_release(releases, "stable", ASSET)["tag_name"], "v1.0.0")

    def test_semver_order(self):
        self.assertLess(lib.version_key("v1.0.0-dev.9"), lib.version_key("v1.0.0-dev.10"))
        self.assertLess(lib.version_key("v1.0.0-dev.10"), lib.version_key("v1.0.0"))
        self.assertLess(lib.version_key("v1.0.0-alpha"), lib.version_key("v1.0.0-alpha.1"))


class _Response(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class FakeOpener:
    def __init__(self, routes):
        self.routes = routes
        self.requests = []

    def open(self, request, timeout):
        url = request.full_url
        self.requests.append(url)
        if url not in self.routes:
            raise OSError(f"unreachable {url}")
        return _Response(self.routes[url])


class DownloadTest(unittest.TestCase):
    def setUp(self):
        self.trust = dev_trust()
        self.directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.directory)
        self.release = write_release(self.directory / "release", "v1.4.0").parent
        base = f"https://github.com/{lib.REPOSITORY}/releases/download/v1.4.0/{ASSET}"
        listing = json.dumps([ReleaseSelectionTest.release("v1.4.0")]).encode()
        self.routes = {
            f"https://api.github.com/repos/{lib.REPOSITORY}/releases?per_page=100": listing,
            base: (self.release / ASSET).read_bytes(),
            base + ".manifest.json": (self.release / (ASSET + ".manifest.json")).read_bytes(),
            base + ".sig": (self.release / (ASSET + ".sig")).read_bytes(),
        }

    def test_download_verifies_and_falls_back_to_the_mirror(self):
        mirrored = {lib.MIRROR + url[len("https://"):]: data for url, data in self.routes.items()}
        for routes, use_mirror in ((self.routes, False), (mirrored, False), (mirrored, True)):
            opener = FakeOpener(routes)
            output = self.directory / "server"
            with contextlib.redirect_stderr(io.StringIO()):
                manifest = lib.download_release(output, PLATFORM, "auto", use_mirror, self.trust, opener)
            self.assertEqual(manifest["version"], "v1.4.0")
            self.assertEqual(output.read_bytes(), (self.release / ASSET).read_bytes())
            self.assertEqual(opener.requests[0].startswith(lib.MIRROR), use_mirror)

    def test_tampered_binary_is_refused(self):
        base = f"https://github.com/{lib.REPOSITORY}/releases/download/v1.4.0/{ASSET}"
        self.routes[base] = self.routes[base] + b"#"
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(lib.InstallError):
            lib.download_release(self.directory / "server", PLATFORM, "auto", False, self.trust,
                                 FakeOpener(self.routes))
        self.assertFalse((self.directory / "server").exists())

    def test_only_github_and_the_mirror_are_allowed(self):
        self.assertTrue(lib.allowed_url("https://objects.githubusercontent.com/x"))
        for url in ("http://github.com/x", "https://evil.example/x", "https://user@github.com/x",
                    "https://github.com.evil.example/x"):
            self.assertFalse(lib.allowed_url(url), url)


class EnvironmentTest(unittest.TestCase):
    def setUp(self):
        self.directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.directory)
        self.env = self.directory / "server.env"

    def prepare(self, **kwargs):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            values = lib.prepare_environment(HERE / "server.env.example", self.env, "/var/lib/shorebird-server",
                                             **kwargs)
        output = out.getvalue() + err.getvalue()
        for name in ("JWT_SECRET", "PATCH_SIGNING_MASTER_KEY", "DEFAULT_ADMIN_PASSWORD", "PATCH_DELIVERY_AES_SECRET"):
            if values.get(name):
                self.assertNotIn(values[name], output, f"{name} was printed")
        return values, output

    def backups(self):
        return [p for p in self.directory.iterdir() if ".before-install-" in p.name]

    def test_first_install_creates_every_secret(self):
        values, output = self.prepare(base="https://patch.example.com")
        self.assertEqual(stat.S_IMODE(self.env.stat().st_mode), 0o640)
        self.assertEqual(len(base64.b64decode(values["PATCH_SIGNING_MASTER_KEY"])), 32)
        self.assertEqual(len(values["JWT_SECRET"]), 64)
        self.assertGreaterEqual(len(values["DEFAULT_ADMIN_PASSWORD"]), 24)
        self.assertEqual(values["DB_PATH"], "/var/lib/shorebird-server/data/shorebird.db")
        self.assertEqual(values["SERVER_BASE_URL"], "https://patch.example.com")
        self.assertIn("Created PATCH_SIGNING_MASTER_KEY", output)

    def test_rerun_preserves_every_existing_value(self):
        first, _ = self.prepare()
        data = self.env.read_bytes()
        second, output = self.prepare()
        self.assertEqual(first, second)
        self.assertEqual(self.env.read_bytes(), data)
        self.assertIn("unchanged", output)
        self.assertEqual(self.backups(), [])

    def test_missing_secrets_are_added_and_existing_kept(self):
        first, _ = self.prepare()
        text = self.env.read_text().replace(f"JWT_SECRET={first['JWT_SECRET']}", "JWT_SECRET=")
        text = text.replace("DB_DRIVER=sqlite", "DB_DRIVER=postgres")
        self.env.write_text(text)
        second, output = self.prepare(listen="127.0.0.1:9090")
        self.assertNotEqual(second["JWT_SECRET"], first["JWT_SECRET"])
        self.assertEqual(second["PATCH_SIGNING_MASTER_KEY"], first["PATCH_SIGNING_MASTER_KEY"])
        self.assertEqual(second["DEFAULT_ADMIN_PASSWORD"], first["DEFAULT_ADMIN_PASSWORD"])
        self.assertEqual(second["DB_DRIVER"], "postgres")
        self.assertEqual((second["SERVER_HOST"], second["SERVER_PORT"]), ("127.0.0.1", "9090"))
        self.assertEqual(len(self.backups()), 1)

    def test_public_defaults_are_replaced(self):
        self.env.write_text("JWT_SECRET=change-me-in-production-use-a-long-random-string\n"
                            "DEFAULT_ADMIN_PASSWORD=admin123\nPATCH_DELIVERY_ENCRYPTION=per_device_aes_gcm\n")
        self.env.chmod(0o600)
        values, output = self.prepare()
        self.assertNotIn("change-me", values["JWT_SECRET"])
        self.assertNotEqual(values["DEFAULT_ADMIN_PASSWORD"], "admin123")
        self.assertTrue(values["PATCH_DELIVERY_AES_SECRET"])
        self.assertIn("signs out every session", output)

    def test_invalid_master_key_is_never_replaced(self):
        self.env.write_text("PATCH_SIGNING_MASTER_KEY=short\n")
        before = self.env.read_bytes()
        with self.assertRaisesRegex(lib.InstallError, "restore the original"):
            self.prepare()
        self.assertEqual(self.env.read_bytes(), before)

    def test_malformed_files_and_arguments(self):
        self.env.write_text("A=1\nA=2\n")
        with self.assertRaises(lib.InstallError):
            self.prepare()
        self.env.unlink()
        for kwargs in ({"listen": "8080"}, {"base": "ftp://x"}, {"base": "https://x/path"}, {"admin_email": "x"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(lib.InstallError):
                self.prepare(**kwargs)

    def test_update_settings_are_created_once(self):
        path = self.directory / "server-update.json"
        with contextlib.redirect_stderr(io.StringIO()):
            lib.prepare_update_settings(HERE / "server-update.json", path, "dev", True)
            self.assertEqual(json.loads(path.read_text()),
                             {"channel": "dev", "use_mirror": True, "auto_update": False,
                              "check_interval_seconds": 86400})
            path.write_text('{"channel":"stable","use_mirror":false,"auto_update":true,"check_interval_seconds":60}')
            before = path.read_bytes()
            lib.prepare_update_settings(HERE / "server-update.json", path, "dev", False)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)


@unittest.skipUnless(shutil.which("go"), "Go is not installed")
class GoCrossCheckTest(unittest.TestCase):
    """The Python verifier accepts what server-update-tool signs, and Go accepts the test signer."""

    @classmethod
    def setUpClass(cls):
        cls.directory = Path(tempfile.mkdtemp())
        cls.tool = cls.directory / "server-update-tool"
        subprocess.run(["go", "build", "-o", str(cls.tool), "./cmd/server-update-tool"], cwd=SERVER, check=True,
                       env=dict(os.environ, CGO_ENABLED="0"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.directory)

    def test_go_signed_release_verifies(self):
        release = self.directory / "go"
        release.mkdir()
        binary = release / ASSET
        binary.write_bytes(fake_binary("v0.5.0-dev.3"))
        subprocess.run([str(self.tool), "sign", "-key", str(DEV_PEM), "-binary", str(binary), "-version",
                        "v0.5.0-dev.3", "-goos", "linux", "-goarch", "amd64", "-out-dir", str(release)], check=True)
        manifest = lib.verify_files(binary, release / (ASSET + ".manifest.json"), release / (ASSET + ".sig"),
                                    PLATFORM, dev_trust(), self.directory / "copy")
        self.assertEqual((manifest["version"], manifest["channel"]), ("v0.5.0-dev.3", "dev"))

    def test_python_signed_zip_verifies_in_go(self):
        release = write_release(self.directory / "py", "v0.6.0").parent
        archive = self.directory / "update.zip"
        with zipfile.ZipFile(archive, "w") as z:
            for name in (ASSET, ASSET + ".manifest.json", ASSET + ".sig", "VERSION"):
                z.write(release / name, name)
        result = subprocess.run([str(self.tool), "verify-zip", "-zip", str(archive), "-goos", "linux", "-goarch",
                                 "amd64", "-trusted", lib.DEVELOPMENT_PUBLIC_KEY, "-allow-development"],
                                capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.strip(), "ok v0.6.0 stable")


class StagedBase(unittest.TestCase):
    """install.sh --root in a temporary prefix, as an unprivileged user."""

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.directory)
        self.root = self.directory / "root"
        self.root.mkdir()
        self.state = self.root / "var/lib/shorebird-server"
        self.target = self.state / "bin/shorebird-server"
        self.env = self.root / "etc/shorebird-server/server.env"

    def install(self, *args, expect=0, env=None, database=("--sqlite",)):
        # Unless a test is about the database, stage a SQLite install (no PostgreSQL tooling).
        result = subprocess.run(["bash", str(HERE / "install.sh"), "--root", str(self.root), "--platform", PLATFORM,
                                 *map(str, args), *database], capture_output=True, text=True,
                                env=dict(os.environ, **(env or {})))
        self.assertEqual(result.returncode, expect, result.stdout + result.stderr)
        return result.stdout + result.stderr

    def snapshot(self):
        return {str(p.relative_to(self.root)): (p.read_bytes() if p.is_file() and not p.is_symlink() else
                                                os.readlink(p) if p.is_symlink() else None)
                for p in sorted(self.root.rglob("*"))}



class StagedInstallTest(StagedBase):
    def test_install_rerun_and_refusals(self):
        binary = write_release(self.directory / "v1", "v1.0.0-dev.1")
        output = self.install("--binary", binary, "--allow-development", "--base-url", "https://patch.example.com")
        self.assertIn("Verified shorebird-server v1.0.0-dev.1", output)
        self.assertEqual(self.target.read_bytes(), binary.read_bytes())
        self.assertEqual((self.state / "bin/VERSION").read_text(), "v1.0.0-dev.1\n")
        self.assertEqual(os.readlink(self.root / "usr/local/bin/shorebird-server"),
                         "/var/lib/shorebird-server/bin/shorebird-server")
        self.assertEqual((self.root / "etc/systemd/system/shorebird-server.service").read_bytes(),
                         (SERVER / "deploy/systemd/shorebird-server.service").read_bytes())
        self.assertEqual(json.loads((self.state / "bin/server-update.json").read_text())["channel"], "dev")
        values = lib.env_values(self.env.read_text())
        self.assertEqual(stat.S_IMODE(self.env.stat().st_mode), 0o640)
        for name in ("JWT_SECRET", "PATCH_SIGNING_MASTER_KEY"):
            self.assertTrue(values[name])
            self.assertNotIn(values[name], output)
        # The generated administrator password is shown exactly once, and kept root-only.
        password = values["DEFAULT_ADMIN_PASSWORD"]
        self.assertEqual(output.count(password), 1)
        initial = self.root / "etc/shorebird-server/initial-admin-password"
        self.assertEqual(initial.read_text().strip(), password)
        self.assertEqual(stat.S_IMODE(initial.stat().st_mode), 0o600)
        self.assertFalse(list((self.root / "var/lib").glob(".shorebird-server-install.*")), "staging dir leaked")

        # Rerun without a source: idempotent, nothing downloaded, nothing changed.
        before = self.snapshot()
        output = self.install("--allow-development")
        self.assertIn("unchanged", output)
        self.assertNotIn(password, output)
        self.assertEqual(self.snapshot(), before)

        # The same signed binary again is fine; a different one points to self-update.
        self.install("--binary", binary, "--allow-development")
        newer = write_release(self.directory / "v2", "v1.0.1")
        output = self.install("--binary", newer, "--allow-development", expect=1)
        self.assertIn("self-update", output)
        self.assertEqual(self.snapshot(), before)

    def test_verification_failures_install_nothing(self):
        binary = write_release(self.directory / "v1", "v1.0.0")
        # The committed pin file holds no production key: DEVELOPMENT-ONLY needs the testing flag.
        output = self.install("--binary", binary, expect=1)
        self.assertIn("nothing was installed", output)
        other = write_release(self.directory / "other", "v1.0.0", seed=OTHER_SEED)
        self.install("--binary", other, "--allow-development", expect=1)
        manifest = binary.parent / (ASSET + ".manifest.json")
        manifest.write_bytes(manifest.read_bytes().replace(b"v1.0.0", b"v1.0.1"))
        self.install("--binary", binary, "--allow-development", expect=1)
        lying = write_release(self.directory / "lying", "v1.0.0", binary=fake_binary("v9.9.9"))
        output = self.install("--binary", lying, "--allow-development", expect=1)
        self.assertIn("reports v9.9.9", output)
        self.assertFalse(self.target.exists())
        self.assertFalse(self.env.exists())

    def test_zip_source_and_dashboard(self):
        release = write_release(self.directory / "r", "v2.1.0").parent
        archive = self.directory / "update.zip"
        with zipfile.ZipFile(archive, "w") as z:
            for name in (ASSET, ASSET + ".manifest.json", ASSET + ".sig", "VERSION"):
                z.write(release / name, name)
        web = self.directory / "web"
        web.mkdir()
        (web / "index.html").write_text("<!DOCTYPE html>")
        self.install("--zip", archive, "--allow-development", "--web-dir", web, "--listen", "127.0.0.1:9000")
        self.assertEqual((self.state / "web/index.html").read_text(), "<!DOCTYPE html>")
        self.assertEqual(json.loads((self.state / "bin/server-update.json").read_text())["channel"], "stable")
        values = lib.env_values(self.env.read_text())
        self.assertEqual((values["SERVER_HOST"], values["SERVER_PORT"]), ("127.0.0.1", "9000"))

    def test_argument_refusals(self):
        self.assertIn("Unknown option", self.install("--bogus", expect=1))
        binary = write_release(self.directory / "v1", "v1.0.0")
        (binary.parent / (ASSET + ".sig")).unlink()
        self.assertIn(".sig next to it", self.install("--binary", binary, expect=1))
        self.assertIn("not both", self.install("--binary", binary, "--zip", binary, expect=1))


# ---------------------------------------------------------------------------
# Database, reverse proxy, host key and source builds


def write_env(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text))


class DatabasePlanTest(unittest.TestCase):
    def setUp(self):
        self.directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.directory)
        self.env = self.directory / "server.env"

    def plan(self, **kwargs):
        return lib.database_plan(self.env, **kwargs)

    def test_first_install_defaults_to_the_local_postgres(self):
        mode, url, socket_dir, port = self.plan()
        self.assertEqual((mode, socket_dir, port), ("local", "/var/run/postgresql", "5432"))
        self.assertEqual(url, "postgres:///shorebird?host=/var/run/postgresql&port=5432&user=shorebird"
                              "&sslmode=disable&connect_timeout=5")
        self.assertNotIn("@", url)  # peer authentication: no password exists
        self.assertEqual(lib.parse_local_database_url(url), ("/var/run/postgresql", "5432"))
        self.assertEqual(self.plan(socket_dir="/run/pg/", port="5433")[2:], ("/run/pg", "5433"))
        self.assertEqual(self.plan(sqlite=True)[0], "sqlite")
        external = "postgres://sb:secret@db.internal:5432/shorebird?sslmode=require"
        self.assertEqual(self.plan(url=external)[:2], ("external", external))

    def test_argument_refusals(self):
        for kwargs in ({"sqlite": True, "url": "postgres://x/y"}, {"sqlite": True, "postgres": True},
                       {"url": "mysql://x/y"}, {"url": "postgres://x/y", "port": "5433"},
                       {"socket_dir": "relative"}, {"socket_dir": "/a/../b"}, {"port": "70000"}):
            with self.assertRaises(lib.InstallError, msg=kwargs):
                self.plan(**kwargs)

    def test_existing_installs_never_switch(self):
        write_env(self.env, "DB_DRIVER=sqlite\nDB_PATH=/var/lib/shorebird-server/data/shorebird.db\n")
        self.assertEqual(self.plan()[0], "sqlite")
        for kwargs in ({"postgres": True}, {"url": "postgres://a@b/c"}, {"socket_dir": "/run/postgresql"}):
            with self.assertRaisesRegex(lib.InstallError, "SQLite; switching to PostgreSQL is not automated"):
                self.plan(**kwargs)
        write_env(self.env, "SERVER_PORT=8080\n")  # an install from before DB_DRIVER was written
        self.assertEqual(self.plan()[0], "sqlite")

        local = lib.local_database_url("/var/run/postgresql", "5432")
        write_env(self.env, f"DB_DRIVER=postgres\nDATABASE_URL='{local}'\n")
        self.assertEqual(self.plan(), ("local", local, "/var/run/postgresql", "5432"))
        self.assertEqual(self.plan(postgres=True, port="5432")[0], "local")
        with self.assertRaisesRegex(lib.InstallError, "refusing to switch to SQLite"):
            self.plan(sqlite=True)
        with self.assertRaisesRegex(lib.InstallError, "another --pg-socket/--pg-port"):
            self.plan(port="5433")
        with self.assertRaisesRegex(lib.InstallError, "--database-url"):
            self.plan(url="postgres://a@b/c")

        write_env(self.env, "DB_DRIVER=postgres\nDATABASE_URL=postgres://a:b@db/c\n")
        self.assertEqual(self.plan()[:2], ("external", "postgres://a:b@db/c"))
        self.assertEqual(self.plan(url="postgres://a:b@db/c")[0], "external")
        for kwargs in ({"url": "postgres://a:b@other/c"}, {"postgres": True}, {"sqlite": True}):
            with self.assertRaises(lib.InstallError, msg=kwargs):
                self.plan(**kwargs)
        write_env(self.env, "DB_DRIVER=postgres\nDATABASE_URL=\n")
        with self.assertRaisesRegex(lib.InstallError, "no DATABASE_URL"):
            self.plan()

    def test_environment_writes_the_plan_once(self):
        template = HERE / "server.env.example"
        url = lib.local_database_url("/var/run/postgresql", "5432")
        with contextlib.redirect_stderr(io.StringIO()):
            values = lib.prepare_environment(template, self.env, "/var/lib/shorebird-server", db_driver="postgres",
                                             db_url=url)
        self.assertEqual((values["DB_DRIVER"], values["DATABASE_URL"]), ("postgres", url))
        # systemd's EnvironmentFile and shlex read the same single value.
        self.assertIn(f"DATABASE_URL='{url}'", self.env.read_text())
        with contextlib.redirect_stderr(io.StringIO()):
            again = lib.prepare_environment(template, self.env, "/x", db_driver="sqlite", db_url="")
        self.assertEqual(again["DB_DRIVER"], "postgres")


class HbaTest(unittest.TestCase):
    def test_rule_is_prepended_once_with_a_backup(self):
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, directory)
        hba = directory / "pg_hba.conf"
        hba.write_text("local all postgres peer\nlocal all all scram-sha-256\n")
        hba.chmod(0o640)
        backup = lib.update_hba(hba)
        text = hba.read_text()
        self.assertTrue(text.startswith(lib.HBA_BEGIN + "\nlocal   shorebird   shorebird   peer\n" + lib.HBA_END))
        self.assertTrue(text.endswith("local all all scram-sha-256\n"))
        self.assertEqual(Path(backup).read_text(), "local all postgres peer\nlocal all all scram-sha-256\n")
        self.assertEqual(stat.S_IMODE(hba.stat().st_mode), 0o640)
        self.assertEqual(lib.update_hba(hba), "")  # idempotent: no change, no backup
        hba.write_text("host all all 0.0.0.0/0 md5\n" + text)  # moved below another rule
        lib.update_hba(hba)
        self.assertTrue(hba.read_text().startswith(lib.HBA_BEGIN))
        self.assertEqual(hba.read_text().count(lib.HBA_BEGIN), 1)
        hba.write_text(lib.HBA_BEGIN + "\n" + lib.HBA_BEGIN + "\n")
        with self.assertRaises(lib.InstallError):
            lib.update_hba(hba)


class CaddyTest(unittest.TestCase):
    def setUp(self):
        self.directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.directory)
        self.caddyfile = self.directory / "Caddyfile"
        self.site = self.directory / "shorebird-server.caddy"

    def write(self, **kwargs):
        options = dict(domain="patch.example.com", upstream="127.0.0.1:8080", email="ops@example.com")
        options.update(kwargs)
        return lib.write_caddy(options["domain"], options["upstream"], options["email"], self.caddyfile, self.site,
                               "/etc/caddy/shorebird-server.caddy")

    def test_stock_caddyfile_is_replaced_and_custom_ones_import(self):
        stock = ("# The Caddyfile is an easy way to configure your Caddy web server.\n#\n:80 {\n"
                 "\t# Set this path to your site's directory.\n\troot * /usr/share/caddy\n\n"
                 "\t# Enable the static file server.\n\tfile_server\n}\n\n# Refer to the Caddy docs\n")
        self.caddyfile.write_text(stock)
        backups = self.write()
        self.assertEqual(self.caddyfile.read_text(), lib.CADDY_MARK + "\nimport /etc/caddy/shorebird-server.caddy\n")
        self.assertEqual([Path(b).read_text() for b in backups], [stock])
        site = self.site.read_text()
        self.assertIn("patch.example.com {\n\ttls ops@example.com\n", site)
        self.assertIn("\treverse_proxy 127.0.0.1:8080\n}", site)
        self.assertEqual(self.write(), [])  # idempotent

        custom = "other.example.com {\n\trespond \"hi\"\n}\n"
        self.caddyfile.write_text(custom)
        self.write(domain="new.example.com", email="")
        self.assertTrue(self.caddyfile.read_text().startswith(custom))
        self.assertEqual(self.caddyfile.read_text().count("import /etc/caddy/shorebird-server.caddy"), 1)
        self.assertNotIn("tls", self.site.read_text())
        self.write(domain="new.example.com", email="")
        self.assertEqual(self.caddyfile.read_text().count("import "), 1)

    def test_refusals(self):
        self.site.write_text("foreign.example.com {\n}\n")
        with self.assertRaisesRegex(lib.InstallError, "not written by this installer"):
            self.write()
        for domain in ("", "localhost", "a b.example.com", "-x.example.com", "patch.example.com/x", "1.2.3.4"):
            with self.assertRaises(lib.InstallError, msg=domain):
                lib.check_domain(domain)
        self.assertEqual(lib.check_domain("Patch.Example.com"), "patch.example.com")


class HostKeyTest(unittest.TestCase):
    def test_created_once_and_never_replaced(self):
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, directory)
        key, trusted = directory / "server-update-signing.pem", directory / "server-update.trusted-keys"
        with contextlib.redirect_stderr(io.StringIO()):
            public = lib.host_key(key, trusted)
        self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
        seed = pem_seed(key)
        self.assertEqual(base64.b64decode(public), sign(seed, b"")[0])
        self.assertEqual(lib.host_trusted_list(trusted), public)
        before = key.read_bytes()
        self.assertEqual(lib.host_key(key, trusted), public)
        self.assertEqual(key.read_bytes(), before)
        trusted.write_text(base64.b64encode(sign(OTHER_SEED, b"")[0]).decode() + "\n")
        with self.assertRaisesRegex(lib.InstallError, "does not hold the public key"):
            lib.host_key(key, trusted)
        key.unlink()
        with self.assertRaisesRegex(lib.InstallError, "restore the key"):
            lib.host_key(key, trusted)
        self.assertFalse(key.exists())
        trusted.unlink()
        key.write_text("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
        key.chmod(0o644)
        with self.assertRaisesRegex(lib.InstallError, "chmod 600"):
            lib.host_key(key, trusted)

    def test_python_key_derivation_matches_the_development_pair(self):
        self.assertEqual(base64.b64encode(lib.ed25519_public(DEV_SEED)).decode(), lib.DEVELOPMENT_PUBLIC_KEY)


class SourceVersionTest(unittest.TestCase):
    def setUp(self):
        self.directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.directory)
        (self.directory / "VERSION").write_text("v0.4.0\n")

    def version(self, ref="", installed="", epoch=1_800_000_000, sha="ab" * 20):
        return lib.source_version(self.directory, sha, epoch, ref, installed)

    def test_tags_branches_and_monotonic_order(self):
        self.assertEqual(self.version("v0.5.0"), "v0.5.0")
        dev = self.version("main")
        self.assertEqual(dev, "v0.4.1-dev.20270115080000.gabababababab")
        self.assertEqual(self.version("v0.5.0-rc.1"), dev)  # only exact stable tags are taken literally
        self.assertEqual(self.version(installed="v0.6.2"), "v0.6.3-dev.20270115080000.gabababababab")
        self.assertEqual(self.version(installed="v0.6.3-dev.1.gx"), "v0.6.3-dev.20270115080000.gabababababab")
        older, newer = self.version(epoch=1_800_000_000), self.version(epoch=1_800_000_060, sha="cd" * 20)
        self.assertLess(lib.version_key(older), lib.version_key(newer))
        self.assertLess(lib.version_key("v0.6.2"), lib.version_key(self.version(installed="v0.6.2")))

    def test_build_flags_match_build_update_zip(self):
        script = (SERVER / "scripts" / "build_update_zip.py").read_text()
        for flag in lib.build_ldflags("V", "T", "K"):
            name = flag.split("=")[0]
            self.assertIn(name.replace("github.com/shorebird-server", "{MODULE}"), script, flag)
        self.assertIn("'-s', '-w'", script)

    def test_go_version_from_go_mod(self):
        mod = self.directory / "go.mod"
        mod.write_text("module x\n\ngo 1.25.0\n\ntoolchain go1.26.10\n")
        self.assertEqual(lib.go_version(mod), "go1.26.10")
        mod.write_text("module x\n\ngo 1.25.3\n")
        self.assertEqual(lib.go_version(mod), "go1.25.3")
        self.assertEqual(lib.go_version(SERVER / "go.mod")[:4], "go1.")


def tar_bytes(entries):
    """entries: [(name, bytes or None for a directory, mode, kind)]"""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data, mode, kind in entries:
            info = tarfile.TarInfo(name)
            info.mode = mode
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = data
                archive.addfile(info)
            else:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class DownloadsForSourceBuildTest(unittest.TestCase):
    def setUp(self):
        self.directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.directory)
        self.go = tar_bytes([("go", None, 0o755, "dir"), ("go/bin/go", b"#!/bin/sh\necho go\n", 0o755, "file"),
                             ("go/src/link", "../../../etc/passwd", 0o777, "symlink")])
        self.index = [{"version": "go1.26.10", "files": [
            {"filename": "go1.26.10.linux-amd64.tar.gz", "os": "linux", "arch": "amd64", "kind": "archive",
             "sha256": hashlib.sha256(self.go).hexdigest()},
            {"filename": "go1.26.10.src.tar.gz", "os": "", "arch": "", "kind": "source", "sha256": "0" * 64}]}]

    def opener(self):
        return FakeOpener({"https://go.dev/dl/?mode=json&include=all": json.dumps(self.index).encode(),
                           "https://dl.google.com/go/go1.26.10.linux-amd64.tar.gz": self.go})

    def test_go_toolchain_is_verified_extracted_and_reused(self):
        with contextlib.redirect_stderr(io.StringIO()):
            goroot = lib.go_toolchain("go1.26.10", self.directory, "linux-amd64", self.opener())
        self.assertEqual(goroot, self.directory / "go1.26.10" / "go")
        self.assertTrue(os.access(goroot / "bin" / "go", os.X_OK))
        self.assertFalse((goroot / "src" / "link").exists(), "links are never extracted")
        reuse = FakeOpener({"https://go.dev/dl/?mode=json&include=all": json.dumps(self.index).encode()})
        self.assertEqual(lib.go_toolchain("go1.26.10", self.directory, "linux-amd64", reuse), goroot)

    def test_go_toolchain_refusals(self):
        with self.assertRaisesRegex(lib.InstallError, "no go1.26.10 archive for linux-arm64"):
            lib.go_toolchain("go1.26.10", self.directory, "linux-arm64", self.opener())
        self.index[0]["files"][0]["sha256"] = "1" * 64
        with self.assertRaisesRegex(lib.InstallError, "SHA-256"), contextlib.redirect_stderr(io.StringIO()):
            lib.go_toolchain("go1.26.10", self.directory, "linux-amd64", self.opener())
        self.assertFalse((self.directory / "go1.26.10").exists())
        with self.assertRaises(lib.InstallError):
            lib.go_toolchain("go1.26.10; rm -rf /", self.directory, "linux-amd64", self.opener())
        self.assertFalse(lib.allowed_url("https://evil.example/go.tar.gz", lib.GO_HOSTS))
        self.assertFalse(lib.allowed_url("http://dl.google.com/go/x.tar.gz", lib.GO_HOSTS))

    def test_unsafe_archives_are_refused(self):
        for entries in ([("x/../../evil", b"x", 0o644, "file")], [("/abs", b"x", 0o644, "file")],
                        [("a/f", b"x", 0o644, "file"), ("b/f", b"x", 0o644, "file")]):
            archive = self.directory / "a.tar.gz"
            archive.write_bytes(tar_bytes(entries))
            target = self.directory / "out"
            shutil.rmtree(target, ignore_errors=True)
            with self.assertRaises(lib.InstallError, msg=entries):
                lib.safe_extract(archive, target, strip_root=True)

    def test_ref_and_source(self):
        sha = "1234567890abcdef" * 2 + "12345678"
        commit = {"sha": sha, "commit": {"committer": {"date": "2026-11-09T12:00:00Z"}}}
        source = tar_bytes([(f"tony-cloud-shorebird-server-{sha[:7]}/{name}", data, 0o644, "file")
                            for name, data in (("go.mod", b"module x\n"), ("VERSION", b"v0.4.0\n"),
                                               ("cmd/server/main.go", b"package main\n"),
                                               ("cmd/server-update-tool/main.go", b"package main\n"))])
        opener = FakeOpener({"https://api.github.com/repos/tony-cloud/shorebird-server/commits/main":
                             json.dumps(commit).encode(),
                             f"https://codeload.github.com/tony-cloud/shorebird-server/tar.gz/{sha}": source})
        self.assertEqual(lib.resolve_ref("main", opener), (sha, 1794225600))
        with contextlib.redirect_stderr(io.StringIO()):
            lib.fetch_source(sha, self.directory / "src", opener)
        self.assertEqual((self.directory / "src" / "VERSION").read_text(), "v0.4.0\n")
        for ref in ("../x", "-rf", "a b"):
            with self.assertRaises(lib.InstallError):
                lib.resolve_ref(ref, opener)


FAKE_GO = r'''#!/usr/bin/env python3
"""Fake Go toolchain for the installer tests: records calls, "builds" scripts."""
import json, os, sys
# The installer passes a clean environment to Go; the configuration sits next to this file.
config = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "fake.json")))
args = sys.argv[1:]
with open(config["log"], "a") as log:
    log.write(json.dumps({"args": args, "env": {k: os.environ.get(k) for k in (
        "GOTOOLCHAIN", "GOFLAGS", "CGO_ENABLED", "GOOS", "GOARCH", "GOENV", "GOCACHE")}}) + "\n")
if args[:2] == ["env", "GOVERSION"]:
    print("go1.26.10")
    sys.exit(0)
assert args[0] == "build", args
out = args[args.index("-o") + 1]
if args[-1] == "./cmd/server-update-tool":
    body = "#!/usr/bin/env python3\nimport sys, os\nsys.path.insert(0, %r)\nimport test_install\ntest_install.fake_tool(sys.argv[1:])\n" % config["tests"]
else:
    flags = [a for a in args if a.startswith("-ldflags=")][0]
    version = flags.split("internal/version.Version=")[1].split()[0]
    trusted = flags.split("internal/updater.TrustedKeys=")[1].split()[0]
    body = "#!/bin/sh\n# trusted %s\nif [ \"$1\" = --version ]; then echo %s; exit 0; fi\nexit 3\n" % (trusted, version)
with open(out, "w") as stream:
    stream.write(body)
os.chmod(out, 0o755)
'''


def fake_tool(argv):
    """server-update-tool sign, as the fake Go toolchain builds it."""
    assert argv[0] == "sign" and "-production" in argv, argv
    option = {argv[i]: argv[i + 1] for i in range(1, len(argv) - 1) if argv[i].startswith("-") and argv[i] != "-production"}
    seed = pem_seed(option["-key"])
    public = base64.b64encode(sign(seed, b"")[0]).decode()
    assert public in option["-trusted"].split(","), "the signing key must be pinned"
    binary = Path(option["-binary"]).read_bytes()
    platform = f"{option['-goos']}-{option['-goarch']}"
    manifest = manifest_bytes(binary, option["-version"], platform=platform)
    out = Path(option["-out-dir"])
    (out / f"shorebird-server-{platform}.manifest.json").write_bytes(manifest)
    (out / f"shorebird-server-{platform}.sig").write_bytes(signature_bytes(manifest, seed))


class FakeLocalServer:
    """The running server's local upload route, for staged upgrades."""

    def __init__(self, bin_dir, version, rollback=False, refuse=None):
        self.bin_dir, self.version, self.rollback, self.refuse = bin_dir, version, rollback, refuse
        self.uploads = []
        self.secret = self.rotate()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def reply(self, code, body):
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def authorized(self):
                return self.headers.get("Authorization") == f"Bearer {owner.secret}"

            def do_GET(self):
                if not self.authorized():
                    return self.reply(401, {"code": "local_secret_invalid"})
                self.reply(200, owner.status())

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                if self.path != "/api/v1/server/update/local" or not self.authorized():
                    return self.reply(401, {"code": "local_secret_invalid"})
                if owner.refuse:
                    return self.reply(409, {"code": owner.refuse})
                owner.uploads.append(body)
                with zipfile.ZipFile(io.BytesIO(body)) as archive:
                    new = archive.read("VERSION").decode().strip()
                self.reply(202, owner.status())
                # The restart: a new core writes a new secret and runs the new version on trial.
                owner.secret = owner.rotate()
                if owner.rollback:
                    owner.rolled_back = new
                else:
                    owner.version, owner.journal = new, "trial"
        self.journal, self.rolled_back = "healthy", ""
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def rotate(self):
        secret = os.urandom(16).hex()
        (self.bin_dir / "server-local-update.secret").write_text(secret + "\n")
        return secret

    def status(self):
        return {"mode": "active", "current_version": self.version, "journal_state": self.journal, "state": "idle",
                "rolled_back_version": self.rolled_back}

    def close(self):
        self.server.shutdown()
        self.server.server_close()


FAKE_PSQL = r'''#!/usr/bin/env python3
"""Fake PostgreSQL client tools: records argv, keeps roles/databases in a JSON file."""
import json, os, sys
name = os.path.basename(sys.argv[0])
state_path = os.environ["FAKE_PG_STATE"]
state = json.load(open(state_path)) if os.path.exists(state_path) else {"roles": [], "databases": []}
with open(os.environ["FAKE_PG_LOG"], "a") as log:
    log.write(json.dumps([name] + sys.argv[1:]) + "\n")
args = sys.argv[1:]
if name == "createuser":
    state["roles"].append(args[-1])
elif name == "createdb":
    state["databases"].append(args[-1])
else:
    sql = args[args.index("-Atqc") + 1]
    database = args[args.index("-d") + 1]
    answers = {
        "SELECT 1;": "1",
        "SELECT count(*) FROM pg_roles WHERE rolname='shorebird';": str(int("shorebird" in state["roles"])),
        "SELECT count(*) FROM pg_database WHERE datname='shorebird';": str(int("shorebird" in state["databases"])),
        "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='shorebird';": "shorebird",
        "SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL;": "0",
        "SHOW hba_file;": os.environ["FAKE_PG_HBA"],
        "SELECT pg_reload_conf();": "t",
    }
    if sql.startswith("SELECT rolcanlogin"):
        print("t")
    elif sql.startswith("SELECT current_user"):
        ok = database == "shorebird" and "shorebird" in state["roles"] and "shorebird" in state["databases"]
        print("t" if ok and "local shorebird" in " ".join(open(os.environ["FAKE_PG_HBA"]).read().split()) else "f")
    else:
        print(answers[sql])
json.dump(state, open(state_path, "w"))
'''


class StagedDatabaseAndProxyTest(StagedBase):
    """--root staging with fake PostgreSQL tools on PATH."""

    def setUp(self):
        super().setUp()
        self.tools = self.directory / "tools"
        self.tools.mkdir()
        for name in ("psql", "createuser", "createdb"):
            (self.tools / name).write_text(FAKE_PSQL)
            (self.tools / name).chmod(0o755)
        self.hba = self.directory / "pg_hba.conf"
        self.hba.write_text("local all postgres peer\nlocal all all scram-sha-256\n")
        self.pg_log = self.directory / "pg.log"
        self.pg_env = {"PATH": f"{self.tools}:{os.environ['PATH']}", "FAKE_PG_STATE": str(self.directory / "pg.json"),
                       "FAKE_PG_LOG": str(self.pg_log), "FAKE_PG_HBA": str(self.hba)}
        self.binary = write_release(self.directory / "v1", "v1.0.0")

    def pg_calls(self):
        return [json.loads(line) for line in self.pg_log.read_text().splitlines()] if self.pg_log.exists() else []

    def test_local_postgres_is_provisioned_once(self):
        output = self.install("--binary", self.binary, "--allow-development", env=self.pg_env, database=())
        values = lib.env_values(self.env.read_text())
        self.assertEqual(values["DB_DRIVER"], "postgres")
        self.assertEqual(lib.parse_local_database_url(values["DATABASE_URL"]), ("/var/run/postgresql", "5432"))
        calls = self.pg_calls()
        self.assertIn(["createuser", "-w", "-h", "/var/run/postgresql", "-p", "5432", "--no-superuser",
                       "--no-createdb", "--no-createrole", "shorebird"], calls)
        self.assertIn(["createdb", "-w", "-h", "/var/run/postgresql", "-p", "5432", "--owner=shorebird", "shorebird"],
                      calls)
        self.assertTrue(self.hba.read_text().startswith(lib.HBA_BEGIN))
        self.assertEqual(len(list(self.directory.glob("pg_hba.conf.before-shorebird-*"))), 1)
        self.assertIn("pg_dump -Fc shorebird", output)
        self.assertIn("peer auth (no password)", output)

        # Rerun: nothing is created again, the rule is not duplicated.
        self.pg_log.unlink()
        self.install(env=self.pg_env, database=())
        names = [call[0] for call in self.pg_calls()]
        self.assertNotIn("createuser", names)
        self.assertNotIn("createdb", names)
        self.assertEqual(len(list(self.directory.glob("pg_hba.conf.before-shorebird-*"))), 1)
        self.assertEqual(self.hba.read_text().count(lib.HBA_BEGIN), 1)
        # Switching to SQLite is refused before anything changes.
        before = self.snapshot()
        self.assertIn("refusing to switch to SQLite", self.install(env=self.pg_env, database=("--sqlite",), expect=1))
        self.assertEqual(self.snapshot(), before)

    def test_sqlite_install_never_switches_to_postgres(self):
        self.install("--binary", self.binary, "--allow-development")
        self.assertEqual(lib.env_values(self.env.read_text())["DB_DRIVER"], "sqlite")
        output = self.install(env=self.pg_env, database=("--postgres",), expect=1)
        self.assertIn("switching to PostgreSQL is not automated", output)
        self.install(env=self.pg_env, database=())  # without options SQLite is kept
        self.assertEqual(self.pg_calls(), [])

    def test_external_database_url_installs_no_local_postgres(self):
        url = "postgres://shorebird:s3cret@db.internal:5432/shorebird?sslmode=require"
        self.install("--binary", self.binary, "--allow-development", env=self.pg_env, database=("--database-url", url))
        self.assertEqual(lib.env_values(self.env.read_text())["DATABASE_URL"], url)
        self.assertEqual(self.pg_calls(), [])
        self.assertIn("another DATABASE_URL", self.install(env=self.pg_env, expect=1, database=(
            "--database-url", "postgres://x:y@elsewhere/z")))

    def test_domain_writes_caddy_and_listens_locally(self):
        output = self.install("--binary", self.binary, "--allow-development", "--domain", "Patch.Example.com",
                              "--acme-email", "ops@example.com", "--admin-email", "me@example.com")
        values = lib.env_values(self.env.read_text())
        self.assertEqual(values["SERVER_BASE_URL"], "https://patch.example.com")
        self.assertEqual((values["SERVER_HOST"], values["SERVER_PORT"]), ("127.0.0.1", "8080"))
        self.assertEqual((self.root / "etc/caddy/Caddyfile").read_text(),
                         lib.CADDY_MARK + "\nimport /etc/caddy/shorebird-server.caddy\n")
        self.assertIn("patch.example.com {\n\ttls ops@example.com\n\tencode zstd gzip\n\treverse_proxy 127.0.0.1:8080\n}",
                      (self.root / "etc/caddy/shorebird-server.caddy").read_text())
        self.assertIn("Public URL:      https://patch.example.com", output)
        self.assertIn("Admin e-mail:    me@example.com", output)
        self.assertIn("SHOREBIRD_HOSTED_URL=https://patch.example.com", output)
        self.assertIn("need --domain", self.install("--acme-email", "x@y.z", expect=1))


class StagedSourceBuildTest(StagedBase):
    """--build-from-source with a local git checkout and a fake Go toolchain."""

    def setUp(self):
        super().setUp()
        self.source = self.directory / "source"
        for relative, text in (("go.mod", "module github.com/shorebird-server\n\ngo 1.25.0\n\ntoolchain go1.26.10\n"),
                               ("VERSION", "v0.4.0\n"), ("cmd/server/main.go", "package main\n"),
                               ("cmd/server-update-tool/main.go", "package main\n")):
            (self.source / relative).parent.mkdir(parents=True, exist_ok=True)
            (self.source / relative).write_text(text)
        self.git("init", "-q", "-b", "main")
        self.commit("first")
        self.goroot = self.directory / "goroot"
        (self.goroot / "bin").mkdir(parents=True)
        (self.goroot / "bin" / "go").write_text(FAKE_GO)
        (self.goroot / "bin" / "go").chmod(0o755)
        self.go_log = self.directory / "go.log"
        (self.goroot / "bin" / "fake.json").write_text(json.dumps({"tests": str(HERE), "log": str(self.go_log)}))
        self.go_env = {}
        self.key = self.root / "etc/shorebird-server/server-update-signing.pem"
        self.trusted = self.root / "etc/shorebird-server/server-update.trusted-keys"

    def git(self, *args):
        subprocess.run(["git", "-C", str(self.source), "-c", "user.name=t", "-c", "user.email=t@e", *args],
                       check=True, capture_output=True)

    def commit(self, message):
        (self.source / "CHANGES").write_text(message + "\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)

    def build(self, *args, expect=0):
        return self.install("--build-from-source", "--source-dir", self.source, "--go-root", self.goroot,
                            "--listen", "127.0.0.1:8080", *args, expect=expect, env=self.go_env)

    def test_first_install_rerun_and_upgrade_through_the_transaction(self):
        output = self.build()
        self.assertEqual(stat.S_IMODE(self.key.stat().st_mode), 0o600)
        public = lib.host_trusted_list(self.trusted)
        version = self.target.read_text().split("echo ")[1].split(";")[0]
        self.assertRegex(version, r"^v0\.4\.1-dev\.[0-9]{14}\.g[0-9a-f]{12}$")
        self.assertIn(f"# trusted {public}\n", self.target.read_text())  # the binary pins only the host key
        self.assertEqual((self.root / "etc/shorebird-server/install-source").read_text(), "source\n")
        self.assertEqual(json.loads((self.state / "bin/server-update.json").read_text())["channel"], "dev")
        self.assertIn("--build-from-source --ref NEWER", output)
        calls = [json.loads(line) for line in self.go_log.read_text().splitlines()]
        server_build = [c for c in calls if c["args"][-1] == "./cmd/server"][0]
        self.assertEqual((server_build["env"]["GOTOOLCHAIN"], server_build["env"]["GOFLAGS"],
                          server_build["env"]["CGO_ENABLED"], server_build["env"]["GOOS"],
                          server_build["env"]["GOARCH"]), ("local", "-mod=readonly", "0", "linux", "amd64"))
        self.assertTrue(server_build["env"]["GOCACHE"].startswith(
            os.path.realpath(self.root / "var/lib/shorebird-server-installer")))
        self.assertEqual(stat.S_IMODE((self.root / "var/lib/shorebird-server-installer").stat().st_mode), 0o700)

        # Same commit again: nothing is built, the key is never replaced.
        key_before, binary_before = self.key.read_bytes(), self.target.read_bytes()
        self.go_log.unlink()
        self.assertIn("already installed", self.build())
        self.assertFalse(self.go_log.exists())
        self.assertEqual(self.key.read_bytes(), key_before)

        # A newer commit is handed to the running server, never copied over the binary.
        time_step = subprocess.run(["git", "-C", str(self.source), "log", "-1", "--format=%ct"],
                                   capture_output=True, text=True).stdout.strip()
        os.environ["GIT_COMMITTER_DATE"] = f"{int(time_step) + 60} +0000"
        try:
            self.commit("second")
        finally:
            del os.environ["GIT_COMMITTER_DATE"]
        fake = FakeLocalServer(self.state / "bin", version)
        self.addCleanup(fake.close)
        output = self.install("--build-from-source", "--source-dir", self.source, "--go-root", self.goroot,
                              "--listen", f"127.0.0.1:{fake.port}", env=self.go_env)
        self.assertEqual(len(fake.uploads), 1)
        upload = self.directory / "upload.zip"
        upload.write_bytes(fake.uploads[0])
        trusted = lib.load_trusted_keys(self.trusted, False)
        manifest = lib.verify_zip(upload, PLATFORM, trusted, self.directory / "uploaded-binary")
        self.assertEqual(lib.version_key(manifest["version"]) > lib.version_key(version), True)
        self.assertIn(f"Upgraded to {manifest['version']}", output)
        self.assertEqual(self.target.read_bytes(), binary_before, "the managed binary is replaced only by the server")
        self.assertEqual(self.key.read_bytes(), key_before)

    def test_failed_trial_is_reported(self):
        self.build()
        version = self.target.read_text().split("echo ")[1].split(";")[0]
        os.environ["GIT_COMMITTER_DATE"] = "2099-01-01T00:00:00 +0000"
        try:
            self.commit("broken")
        finally:
            del os.environ["GIT_COMMITTER_DATE"]
        fake = FakeLocalServer(self.state / "bin", version, rollback=True)
        self.addCleanup(fake.close)
        output = self.install("--build-from-source", "--source-dir", self.source, "--go-root", self.goroot,
                              "--listen", f"127.0.0.1:{fake.port}", env=self.go_env, expect=1)
        self.assertIn("rolled back", output)

    def test_refusals(self):
        (self.source / "VERSION").write_text("v9.9.9\n")
        self.assertIn("uncommitted changes", self.build(expect=1))
        self.git("checkout", "--", "VERSION")
        self.assertIn("drop --binary/--zip", self.build("--zip", self.directory / "x.zip", expect=1))
        self.assertIn("need --build-from-source", self.install("--ref", "main", expect=1))
        # A server installed from a signed release cannot take host builds.
        self.install("--binary", write_release(self.directory / "rel", "v1.0.0"), "--allow-development")
        self.assertIn("installed from a signed release", self.build(expect=1))
        self.assertFalse(self.key.exists())


class LocalUpdateTest(unittest.TestCase):
    def test_refusals_are_explained_and_nothing_waits(self):
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, directory)
        archive = directory / "u.zip"
        archive.write_bytes(b"PK")
        fake = FakeLocalServer(directory, "v1.0.0", refuse="update_trial_in_progress")
        self.addCleanup(fake.close)
        with self.assertRaisesRegex(lib.InstallError, "still on trial"):
            lib.local_update(archive, f"http://127.0.0.1:{fake.port}", directory, "v1.0.1", seconds=5)
        (directory / "server-local-update.secret").unlink()
        with self.assertRaisesRegex(lib.InstallError, "cannot take a local update"):
            lib.local_update(archive, f"http://127.0.0.1:{fake.port}", directory, "v1.0.1", seconds=5)


class DependenciesTest(unittest.TestCase):
    """install_dependencies.sh with fake package tools on a minimal PATH."""

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.directory)
        self.bin = self.directory / "bin"
        self.bin.mkdir()
        self.log = self.directory / "apt.log"
        self.tool("dpkg-query", "exit 1")
        self.tool("apt-get", f'echo "apt-get $*" >> {self.log}')
        self.tool("apt-cache", "exit 0")

    def tool(self, name, body):
        (self.bin / name).write_text(f"#!/bin/sh\n{body}\n")
        (self.bin / name).chmod(0o755)

    def run_dependencies(self, *args):
        # Only the fakes and grep are on PATH, and the PostgreSQL install locations are
        # probed under an empty prefix, so the host's own PostgreSQL (CI images) cannot leak in.
        grep = self.bin / "grep"
        if not grep.exists():
            grep.symlink_to(shutil.which("grep"))
        script = f'source {HERE / "install_dependencies.sh"}; shorebird_install_dependencies "$@"'
        return subprocess.run(["/bin/bash", "-c", script, "deps", *args], capture_output=True, text=True,
                              env={"PATH": str(self.bin), "SHOREBIRD_DEPENDENCY_ROOT": str(self.directory)})

    def apt(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_missing_postgres_is_installed_with_apt(self):
        result = self.run_dependencies("false", "local", "/nonexistent", "5432", "false")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.apt(), ["apt-get update", "apt-get install -y --no-upgrade postgresql"])

    def test_existing_postgres_and_clients_install_nothing(self):
        for name in ("postgres", "psql", "createuser", "createdb"):
            self.tool(name, "exit 0")
        result = self.run_dependencies("false", "local", "/nonexistent", "5432", "false")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Reusing the existing PostgreSQL", result.stderr)
        self.assertEqual(self.apt(), [])
        self.assertEqual(self.run_dependencies("false", "external", "-", "-", "false").returncode, 0)
        self.assertEqual(self.apt(), [])

    def test_refusals_and_caddy(self):
        result = self.run_dependencies("true", "local", "/nonexistent", "5432", "false")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--skip-packages", result.stderr)
        self.tool("dpkg-query", "echo 'install ok installed'")
        result = self.run_dependencies("false", "local", "/nonexistent", "5432", "false")
        self.assertIn("repair it", result.stderr)
        self.tool("dpkg-query", "exit 1")
        self.tool("apt-cache", "exit 100")
        result = self.run_dependencies("false", "sqlite", "-", "-", "true")
        self.assertIn("no caddy package", result.stderr)
        self.assertEqual(self.apt(), ["apt-get update"])
        (self.bin / "apt-get").unlink()
        result = self.run_dependencies("false", "local", "/nonexistent", "5432", "false")
        self.assertIn("not a Debian/Ubuntu system", result.stderr)


if __name__ == "__main__":
    unittest.main()
