# Implementation roadmap

Status reviewed against the repository on 2026-10-15. This is the central checklist;
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
  encrypted local storage, recovery, and passphrase rewrapping (not yet exposed in clients).
- [x] Ten local identity tests, including independent public-key/fingerprint fixtures.
- [x] Proposed contracts for nine sharing API operations, per-step test actions, and an
  executable schema-validation gate wired into GitHub Actions.
- [x] Reconciled stale implementation descriptions and centralized this checklist.

## Next milestone: automatic per-user group-key delivery

Selected next milestone. **In progress; end-to-end delivery is not implemented.**
The local identity foundation and API/test specifications are complete. Group members currently share an
unlock passphrase through a separate trusted channel. The intended outcome is that an
enrolled member can unlock an authorized group using their local user key material,
without manually exchanging the group's passphrase.

Each step has [test actions](testing/group-key-delivery.md) and the proposed endpoints
have [API contracts](api/group-key-delivery.md). Schema validation is wired into CI and
passes locally; a remote run for these changes is pending. Runtime sharing API and
client workflow tests remain planned until their features are implemented.

Implementation work:

- [x] Document the recipient-key enrollment and trust model, key-package format, recovery
  behavior, and compatibility with both standard and experimental hybrid collections:
  [implementation proposal](decisions/0002-per-user-group-key-delivery.md). Runtime
  package-delivery implementation and package protocol-vector validation remain pending.
- [x] Implement shared client-core recipient identity generation, encrypted local storage,
  fingerprint-pinned recovery, and passphrase rewrapping. See [identity format](identity-format.md).
  CLI/web enrollment interfaces and server-backed new-device enrollment remain pending.
- [ ] **Next action:** persist verified contact identities and enforce key-change handling.
  Local fingerprints/self-signatures exist; trusted contact pins, first-contact verification,
  and changed-key blocking are not implemented.
- [ ] Implement authenticated enrollment, identity replacement, public-directory lookup,
  and encrypted identity-bundle synchronization APIs with revision checks.
- [ ] Allow an authorized unlocked client to encrypt group access material for each
  enrolled recipient; store and deliver only encrypted packages through the API.
- [ ] Bind packages to the collection, recipient, key version, and encryption mode, and
  reject tampered, mismatched, stale, or unauthorized packages.
- [ ] Version and migrate persistent data without destroying existing passphrase stores;
  preserve a documented recovery path and reject unsupported formats safely.
- [ ] Integrate enrollment, package creation/retrieval, and group unlock into CLI and web.
- [ ] Make pending delivery visible when a recipient is unenrolled or no authorized
  unlocked client is available. A server with no keys cannot create these grants alone.
- [ ] Cover permissions, disabled users, membership races, retries, conflicts, migration,
  and CLI/WASM interoperability with behavioral tests.

Completion requires two independently enrolled users to access a shared collection
without exchanging a group passphrase, while an unenrolled or unauthorized user cannot
obtain usable access. Read-only membership must still reject writes. Plaintext private
keys and group keys must never enter server storage, logs, or API payloads.

## Verification status for this development batch

- [x] Local workspace Rust tests: 32 passed, including 10 new identity tests.
- [x] Formatting and workspace Clippy with warnings denied.
- [x] WASM target compilation check for the web crate and shared identity core.
- [x] License declaration gate: 272 resolved packages accepted.
- [x] API contract gate: OpenAPI, nine operation mappings, nine schema fixtures.
- [x] Documentation links/anchors and whitespace checks.
- [ ] Remote CI for this batch, including Linux/Windows, browser, and container jobs.
- [ ] Browser identity workflow and live sharing API tests (features not implemented).

These results describe local checks already run. The WASM check does not establish a
working browser enrollment flow, and schema validation does not establish API behavior.

## Following milestone: membership-change key rotation

- [ ] Generate fresh group encryption material and re-encrypt the current collection.
- [ ] Deliver replacement packages only to remaining authorized recipients.
- [ ] Commit the key version, snapshot, and grants consistently under concurrent edits.
- [ ] Define safe behavior while rotation is pending; reject stale-key writes and recover
  from interrupted rotation without silently losing data.
- [ ] Test that removed recipients cannot decrypt new revisions using old material.

Removing membership already blocks API access. Cryptographic exclusion additionally
requires rotation, not just passphrase rewrapping or package deletion. Neither delivery
nor rotation can erase old ciphertext, keys, copied secrets, or Git history.

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
