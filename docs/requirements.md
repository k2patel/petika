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

## Security direction

Use client-side vault encryption with optional, explicitly configured recovery.
Separate encryption method from key ownership and account authentication. Do not
introduce a universal server-held vault key. Personal, shared and company vaults
have explicit access and recovery boundaries; GPG remains import/interoperability
tooling, and server push-backup credentials remain separate from vault keys.

Pursue the strongest practical alignment with NIST, OWASP and relevant assurance
and privacy guidance for every deployment, independent of audience size. Track
technical controls, operating duties and external validation separately. See the
[accepted decision](decisions/0003-security-and-recovery-baseline.md) and
[implementation and evidence plan](security-alignment-plan.md).

## Implemented experimental capabilities

The CLI and Rust/WASM web client support local encryption, password management,
standard and experimental hybrid protection, and encrypted snapshot import/export.
Native GPG import preserves the source store. Website TOTP is implemented for saved
logins; it is separate from account MFA.

The API is authoritative, with revision-checked collection snapshots and a one-way
encrypted Git mirror. Managed accounts, browser-approved CLI sessions, personal/group
collections, and read/edit permissions are implemented. Legacy groups use separately shared passphrases; migrated groups use verified recipient
packages and explicit fresh-key rotation. Setup supports browser and unattended
provisioning; persistence uses versioned JSON files.

The shared client core also generates recipient identities and supports encrypted local
storage, fingerprint-checked recovery, passphrase rewrapping, verified contact pins,
and key-change suspension. CLI/web enrollment, verified delivery, trusted restore, migration, and rotation use this
shared core.

## Next milestone and remaining requirements

Per-user group-key delivery and explicit membership-change rotation are implemented
experimentally. Track remaining work in the [roadmap](roadmap.md).

Browser extensions/autofill, mobile apps, native biometrics, full GPG key-management UI,
OS credential storage, optional OIDC, account MFA/passkeys, recovery, and audit trails
remain unfinished. Payment cards and full 1Password parity remain outside the initial
scope; basic user/group administration is already implemented.

## Open decisions

The recipient enrollment/verification design is [documented](decisions/0002-per-user-group-key-delivery.md)
and implemented. Individual item-sharing semantics, native UI stacks and supported OS versions, native auto-lock
policy, and deployment-specific recovery objectives still need decisions. The
[recovery runbook](recovery.md) defines the baseline backup retention policy. The web client
already has configurable inactivity locking. Deployment manifests target a single
server with persistent filesystem storage; multi-replica operation is unsupported.
