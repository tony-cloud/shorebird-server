# Server update signing keys

`server-update.DEVELOPMENT-ONLY.pem` (public key in
`server-update.DEVELOPMENT-ONLY.pub`) is a deliberately public Ed25519 key for
local builds, tests and end-to-end runs. It protects nothing. A binary accepts
it only when it was linked with `updater.DevelopmentTrust=allowed`, which
`scripts/build_update_zip.py --development` does and release builds never do;
`--production` and the release CI refuse it.

The production key is never committed. See `docs/SELF_UPDATE.md`, "Signing key".
