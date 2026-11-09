# Server update signing keys

`server-update.DEVELOPMENT-ONLY.pem` (public key in
`server-update.DEVELOPMENT-ONLY.pub`) is a deliberately public Ed25519 key for
local builds, tests and end-to-end runs. It protects nothing. A binary accepts
it only when it was linked with `updater.DevelopmentTrust=allowed`, which
`scripts/build_update_zip.py --development` does and release builds never do;
`--production` and the release CI refuse it.

The production key is never committed. See `docs/SELF_UPDATE.md`, "Signing key".

`server-update.trusted-keys` lists the production public keys (base64, one per
line) that `deploy/linux/install.sh` pins to verify a release before
installing it. It is public and is written by shorebird-workspace
`scripts/provision_release_keys.py --write-repo-pins`; it stays empty until
the operator provisions the production key, and the installer then refuses
every release (the DEVELOPMENT-ONLY key needs `--allow-development`).
