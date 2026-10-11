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

## Not implemented

All password management and platform features. TOTP, passkeys, payment cards,
enterprise administration, and full 1Password feature parity are outside the initial scope.

## Decisions needed before functional implementation

API-authoritative sync versus two-way Git sync, authentication provider and enrollment,
cryptographic format and key lifecycle, sharing permissions, platform UI technologies,
auto-lock durations, supported OS versions, deployment storage, and backup retention.
The discussion favored an API-based Rust CLI with offline use and an encrypted Git
mirror, but that transport choice has not been explicitly finalized.
