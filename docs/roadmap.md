# Implementation roadmap

Status reviewed against the repository on 2026-10-17. This is the central checklist;
feature guides describe current behavior. Checked items are implemented experimental
capabilities, not a production-readiness certification.

## Implemented

- [x] Rust core, offline CLI password management, standard and experimental hybrid encryption.
- [x] Rust/WASM web client: search, generation, editing, reveal/copy, encrypted import/export.
- [x] Website TOTP from setup keys/URIs; separate from Petika account MFA.
- [x] Local GPG-store import that leaves source files unchanged.
- [x] Managed accounts, personal/group collections, and API-enforced read/edit permissions.
- [x] Browser-approved CLI sessions, revocation, and explicit encrypted collection pull/push.
- [x] API-authoritative snapshot revisions, conflict rejection, journals, and local Git mirrors.
- [x] Browser/unattended setup, versioned JSON persistence, and migration backups.
- [x] Distroless packaging, Kubernetes/Podman manifests, cross-platform Rust CI, browser checks.
- [x] Light/dark branding with Indian motifs and Devanagari binary digits.
- [x] Shared client-core recipient identity generation, signed public fingerprints,
  encrypted local storage, recovery, and passphrase rewrapping; CLI/web enrollment and restore.
- [x] Local identity and verified-contact tests, including independent public-key/fingerprint
  fixtures, changed-key rejection, encrypted recovery, and migration backups.
- [x] Contracts for ten sharing API operations, per-step test actions, and an
  executable schema-validation gate wired into GitHub Actions.
- [x] Reconciled stale implementation descriptions and centralized this checklist.

## Per-user group access and membership rotation

Implemented experimental capabilities. See [group-access workflow](group-access.md) and
[wire format](key-package-format.md) for usage, compatibility, and recovery limits.

- [x] Deployment-bound identities, encrypted local/recovery bundles, and verified contact pins.
- [x] Authenticated enrollment, public directory, identity replacement, and bundle CAS APIs.
- [x] Signed HPKE packages bound to deployment, collection, mode, epoch, recipient, issuer,
  and membership generation; Standard and pinned experimental X-Wing draft-06 delivery.
- [x] Independent canonical/HPKE fixtures and upstream hybrid KEM vectors.
- [x] Explicit v1-to-v2 migration with preserved original ciphertext backup and recovery wrapper.
- [x] Atomic snapshot/grant journals, bounded pages and batches, persisted retry receipts,
  membership rechecks, and legacy-upload downgrade rejection.
- [x] CLI and browser enrollment, trusted restore, contact verification, delivery, and unlock.
- [x] Visible pending enrollment/delivery; server never manufactures missing grants.
- [x] Fresh group keys, snapshot re-encryption, and replacement grants at the next epoch.
- [x] Block recipient-enabled writes while rotation is required; preserve failed drafts.
- [x] Explicit retry of saved enrollment and access transactions without generating new keys.
- [x] Exclude identity directories and grants from ciphertext-only Git recovery mirrors.
- [x] Two-user CLI → WASM → CLI sharing and rotation in both modes, without a shared
  group passphrase; reader/admin-only denials, removal, stale epoch/revision rejection,
  restart retries, journal failures, and original-backup preservation tests.

Membership removal denies API access immediately. A remaining unlocked editor must perform
rotation for cryptographic exclusion from new ciphertext. Rotation cannot erase old keys,
old snapshots, copied secrets, or Git history. Unenrolled/unverified remaining members stay
pending until an editor can issue grants. Larger rosters use batches of 100.

## Verification for this development batch

- [x] Previous pushed baseline `cb9ac57`: GitHub Actions passed.
- [x] Native core/package tests and Standard/Hybrid server delivery/rotation integration.
- [x] Existing browser regressions: setup, encryption, OTP, permissions, themes, mobile layout.
- [x] Two independently enrolled users: native grants unlock in WASM; browser rotation grants
  unlock in native CLI, in both encryption modes.
- [x] Independent Python HPKE/header/signature fixtures and draft-06 adapter vectors.
- [x] WASM release compilation and workspace compilation/Clippy during development.
- [x] Final local verification: 57 Rust tests; 12 operation mappings and 47 static/runtime
  schema fixtures; dependency licenses accepted for 287 packages; documentation links and whitespace.
- [ ] Remote CI for the new implementation.

Further hardening remains: exhaustive power-loss fault injection, independent cryptographic
review, multi-device trust-conflict merging UX, and identity replacement UI. The identity
replacement API already exists; it is intentionally separate from enrollment retry.

## Remaining backlog

- [ ] Chromium/Firefox extensions and explicit, destination-checked autofill.
- [ ] iOS/Android apps, desktop native messaging, and configurable biometric unlock.
- [ ] Full GPG key creation/export/expiry/revocation UI.
- [ ] OTP QR scanning.
- [ ] Optional OIDC, account MFA/passkeys, account recovery, and audit trails.
- [ ] OS-backed CLI credential storage and private-CA trust configuration.
- [ ] Individual selected-item sharing semantics beyond existing collection sharing.
- [ ] Backup retention policy, historical restore tooling, and clean-host recovery drills.
- [ ] Independent security review, accessibility review, native-platform validation,
  and real-cluster deployment hardening.
- [ ] Simplified favicon.

Platform stacks, supported OS versions, recovery objectives, and later feature ordering
remain open. See [requirements](requirements.md), [architecture](architecture.md), and
[recovery](recovery.md) for constraints.
