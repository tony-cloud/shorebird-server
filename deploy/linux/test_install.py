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
import tempfile
import unittest
import zipfile

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
        for name in ("install.sh", "install_body.sh"):
            subprocess.run(["bash", "-n", str(HERE / name)], check=True)

    @unittest.skipUnless(shutil.which("shellcheck"), "shellcheck is not installed")
    def test_shellcheck(self):
        subprocess.run(["shellcheck", "-S", "warning", str(HERE / "install_body.sh")], check=True)

    def test_bundle_has_no_private_material(self):
        text = (HERE / "install.sh").read_text()
        self.assertNotIn("PRIVATE KEY", text)
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


class StagedInstallTest(unittest.TestCase):
    """install.sh --root in a temporary prefix, as an unprivileged user."""

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.directory)
        self.root = self.directory / "root"
        self.root.mkdir()
        self.state = self.root / "var/lib/shorebird-server"
        self.target = self.state / "bin/shorebird-server"
        self.env = self.root / "etc/shorebird-server/server.env"

    def install(self, *args, expect=0):
        result = subprocess.run(["bash", str(HERE / "install.sh"), "--root", str(self.root), "--platform", PLATFORM,
                                 *map(str, args)], capture_output=True, text=True)
        self.assertEqual(result.returncode, expect, result.stdout + result.stderr)
        return result.stdout + result.stderr

    def snapshot(self):
        return {str(p.relative_to(self.root)): (p.read_bytes() if p.is_file() and not p.is_symlink() else
                                                os.readlink(p) if p.is_symlink() else None)
                for p in sorted(self.root.rglob("*"))}

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
        for name in ("JWT_SECRET", "PATCH_SIGNING_MASTER_KEY", "DEFAULT_ADMIN_PASSWORD"):
            self.assertTrue(values[name])
            self.assertNotIn(values[name], output)
        self.assertFalse(list((self.root / "var/lib").glob(".shorebird-server-install.*")), "staging dir leaked")

        # Rerun without a source: idempotent, nothing downloaded, nothing changed.
        before = self.snapshot()
        output = self.install("--allow-development")
        self.assertIn("unchanged", output)
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


if __name__ == "__main__":
    unittest.main()
