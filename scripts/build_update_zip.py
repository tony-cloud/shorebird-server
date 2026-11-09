#!/usr/bin/env python3
"""Build signed shorebird-server update artifacts, exactly as the release CI does.

For each target this links the server with its version and pinned update
signing keys, signs a manifest with server-update-tool, verifies the result
the way the server will, and writes:

  OUT/<version>/release/<asset>                 raw binary      (GitHub release assets)
  OUT/<version>/release/<asset>.manifest.json   signed manifest
  OUT/<version>/release/<asset>.sig             Ed25519 signature
  OUT/<version>/release/VERSION
  OUT/<version>/shorebird-server-update-<goos>-<goarch>-<version>.zip   (upload)

Version: --version, or the next patch of max(VERSION file, v* tags) as
vX.Y.(Z+1)-dev.<commit UTC time>.g<commit12> (a dev-channel build). A version
without a prerelease suffix is a stable build. The commit time (not the wall
clock) keeps every target of one commit on the same version.

Keys: production builds take --key (PKCS#8 PEM, never printed or copied) and
--trusted-keys (the base64 public keys the binary pins; the signing key must be
one of them). --development uses the committed DEVELOPMENT-ONLY key instead and
links a binary that accepts it; never deploy such a binary.

Examples (from the shorebird-server directory):
  python3 scripts/build_update_zip.py --out ../../temp/server-update --development --target darwin-arm64
  python3 scripts/build_update_zip.py --out DIR --production --key KEY.pem \\
      --trusted-keys "$SHOREBIRD_SERVER_UPDATE_PUBLIC_KEYS" --target linux-amd64 --target linux-arm64
Upload a ZIP as an administrator:
  curl -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/zip' \\
       --data-binary @ZIP https://HOST/api/v1/admin/server/update/upload
"""
import argparse
import datetime
import hashlib
import os
from pathlib import Path
import platform as host_platform
import re
import subprocess
import sys
import tempfile
import zipfile

TARGETS = ['linux-amd64', 'linux-arm64', 'darwin-amd64', 'darwin-arm64', 'windows-amd64']
MODULE = 'github.com/shorebird-server'
DEVELOPMENT_KEY = 'signing/server-update.DEVELOPMENT-ONLY.pem'
DEVELOPMENT_PUBLIC_KEY = 'a0ZEK+btwcAvqSxqsi4jT7YFIVj9AecHhANwfESYE4w='
STABLE = re.compile(r'v(\d+)\.(\d+)\.(\d+)')
VERSION = re.compile(r'v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?')


def git(source: Path, *args: str) -> str:
    return subprocess.check_output(['git', *args], cwd=source, text=True).strip()


def host_target() -> str:
    machine = host_platform.machine().lower()
    arch = {'x86_64': 'amd64', 'amd64': 'amd64', 'arm64': 'arm64', 'aarch64': 'arm64'}.get(machine, machine)
    return f'{sys.platform.replace("win32", "windows")}-{arch}'


def default_version(source: Path, dirty: bool) -> tuple[str, datetime.datetime]:
    commit = git(source, 'rev-parse', 'HEAD')
    when = datetime.datetime.fromtimestamp(int(git(source, 'show', '-s', '--format=%ct', 'HEAD')), datetime.timezone.utc)
    base = (source / 'VERSION').read_text().strip()
    if not STABLE.fullmatch(base):
        raise SystemExit('VERSION must contain a stable vMAJOR.MINOR.PATCH')
    tags = git(source, 'tag', '--list', 'v*').splitlines()
    major, minor, patch = max(tuple(map(int, m.groups())) for value in [base, *tags] if (m := STABLE.fullmatch(value)))
    version = f'v{major}.{minor}.{patch + 1}-dev.{when:%Y%m%d%H%M%S}.g{commit[:12]}'
    return (version + '.dirty' if dirty else version), when


def main() -> None:
    source = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--out', type=Path, help='output directory (outside the source tree)')
    parser.add_argument('--target', action='append', choices=TARGETS, help='repeatable; default: this host')
    parser.add_argument('--key', type=Path, help='PKCS#8 Ed25519 signing key (production)')
    parser.add_argument('--trusted-keys', default=os.environ.get('SHOREBIRD_SERVER_UPDATE_PUBLIC_KEYS', ''),
                        help='comma-separated base64 public keys pinned into the binary')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--development', action='store_true', help='sign with and trust the DEVELOPMENT-ONLY key')
    mode.add_argument('--production', action='store_true', help='refuse the DEVELOPMENT-ONLY key')
    parser.add_argument('--version', help='override the computed version (vMAJOR.MINOR.PATCH[-pre])')
    parser.add_argument('--allow-dirty', action='store_true', help='build with uncommitted changes')
    parser.add_argument('--print-version', action='store_true', help='print the computed version and exit')
    args = parser.parse_args()

    dirty = bool(git(source, 'status', '--porcelain', '--untracked-files=no'))
    version, when = default_version(source, dirty)
    if args.version:
        version = args.version
    if not VERSION.fullmatch(version):
        raise SystemExit(f'Invalid version {version!r}')
    if args.print_version:
        print(version)
        return
    if args.out is None:
        raise SystemExit('--out is required')
    if dirty and not args.allow_dirty:
        raise SystemExit('The source tree has uncommitted changes; commit first or pass --allow-dirty')
    out = args.out.resolve()
    if out == source or source in out.parents:
        raise SystemExit('--out must be outside the server source tree')

    if args.development:
        key = source / DEVELOPMENT_KEY
        trusted = DEVELOPMENT_PUBLIC_KEY
    else:
        if args.key is None or not args.trusted_keys:
            raise SystemExit('--key and --trusted-keys are required (or use --development)')
        key, trusted = args.key, args.trusted_keys.strip()
        if DEVELOPMENT_PUBLIC_KEY in trusted.split(','):
            raise SystemExit('Refusing to pin the DEVELOPMENT-ONLY key without --development')
    channel = 'dev' if '-' in version else 'stable'

    release = out / version / 'release'
    release.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ, CGO_ENABLED='0')
    ldflags = ['-s', '-w', f'-X {MODULE}/internal/version.Version={version}',
               f'-X {MODULE}/internal/version.BuildTime={when:%Y-%m-%dT%H:%M:%SZ}',
               f'-X {MODULE}/internal/updater.TrustedKeys={trusted}']
    if args.development:
        ldflags.append(f'-X {MODULE}/internal/updater.DevelopmentTrust=allowed')
    (release / 'VERSION').write_text(version + '\n')
    with tempfile.TemporaryDirectory(dir=out) as temporary:
        tool = Path(temporary) / 'server-update-tool'
        # The signing tool runs here, so build it for the host even when the
        # caller cross-compiles (CI legs export GOOS/GOARCH for the target).
        host_environment = {k: v for k, v in environment.items() if k not in ('GOOS', 'GOARCH', 'GOARM', 'GOAMD64', 'GOARM64')}
        subprocess.run(['go', 'build', '-mod=readonly', '-trimpath', '-o', str(tool), './cmd/server-update-tool'],
                       cwd=source, env=host_environment, check=True)
        for label in args.target or [host_target()]:
            if label not in TARGETS:
                raise SystemExit(f'Unsupported target {label}')
            goos, goarch = label.split('-')
            asset = f'shorebird-server-{goos}-{goarch}' + ('.exe' if goos == 'windows' else '')
            binary = release / asset
            subprocess.run(['go', 'build', '-mod=readonly', '-trimpath', '-ldflags=' + ' '.join(ldflags),
                            '-o', str(binary), './cmd/server'], cwd=source,
                           env=dict(environment, GOOS=goos, GOARCH=goarch), check=True)
            sign = [str(tool), 'sign', '-key', str(key), '-binary', str(binary), '-version', version,
                    '-goos', goos, '-goarch', goarch, '-out-dir', str(release), '-trusted', trusted]
            if args.production:
                sign.append('-production')
            subprocess.run(sign, check=True)
            archive = out / version / f'shorebird-server-update-{goos}-{goarch}-{version}.zip'
            with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
                for name in [asset, asset + '.manifest.json', asset + '.sig', 'VERSION']:
                    z.write(release / name, name)
            verify = [str(tool), 'verify-zip', '-zip', str(archive), '-goos', goos, '-goarch', goarch, '-trusted', trusted]
            if args.development:
                verify.append('-allow-development')
            subprocess.run(verify, check=True, stdout=subprocess.DEVNULL)
            print(f'{archive}  {hashlib.sha256(archive.read_bytes()).hexdigest()}  {version}  {channel}')


if __name__ == '__main__':
    main()
