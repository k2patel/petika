# Product requirements

## Agreed requirements

- Name: Petika; CLI: `petika`; original implementation licensed MIT.
- One repository for a self-hosted server, clients, deployment assets, and docs.
- Rust for core, server, CLI, and shared integration logic. No npm.
- Chromium and Firefox extensions on Windows, macOS, and Linux; iOS and Android apps.
- Password search, generation, save, edit, copy, and autofill.
- One person's many devices, with selected passwords shareable with other users.
- Biometrics enabled by default on supported devices, with an on/off setting.
  Authenticate on unlock, not on every secret access. Provide deliberate passphrase
  fallback when biometrics fail or are unavailable; never silently unlock.
- Import existing GPG-encrypted password stores locally; legacy `pass` format and CLI
  compatibility are not required after import. Do not modify the source store.
- Encrypted Git copies and recoverable backups must be addressed in the design.
- Cargo and native binary distribution; no domain purchase required.

## Implemented experimental capabilities

The CLI and Rust/WASM web client support local encryption, password management,
standard and experimental hybrid protection, and encrypted snapshot import/export.
Native GPG import preserves the source store. Website TOTP is implemented for saved
logins; it is separate from account MFA.

The API is authoritative, with revision-checked collection snapshots and a one-way
encrypted Git mirror. Managed accounts, browser-approved CLI sessions, personal/group
collections, and read/edit permissions are implemented. Group passphrases currently
travel through a separate trusted channel. Setup supports browser and unattended
provisioning; persistence uses versioned JSON files.

The shared client core also generates recipient identities and supports encrypted local
storage, fingerprint-checked recovery, passphrase rewrapping, verified contact pins,
and key-change suspension. This foundation is not
yet connected to CLI/web enrollment or server-backed group-key delivery.

## Next milestone and remaining requirements

**Next: automatic per-user group-key delivery**, followed by membership-change key
rotation. Track implementation and acceptance in the [roadmap](roadmap.md).

Browser extensions/autofill, mobile apps, native biometrics, full GPG key-management UI,
OS credential storage, optional OIDC, account MFA/passkeys, recovery, and audit trails
remain unfinished. Payment cards and full 1Password parity remain outside the initial
scope; basic user/group administration is already implemented.

## Open decisions

The recipient enrollment/verification design is [documented](decisions/0002-per-user-group-key-delivery.md)
but awaits API and client integration. Fresh group-key rotation, individual item-sharing semantics, native UI stacks and supported OS versions, native auto-lock
policy, and backup retention/recovery objectives still need decisions. The web client
already has configurable inactivity locking. Deployment manifests target a single
server with persistent filesystem storage; multi-replica operation is unsupported.
