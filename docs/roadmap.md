# Implementation roadmap

Status reviewed against the repository on 2026-10-18. This is the central checklist;
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
- [x] Remote CI for group delivery/rotation: all six jobs passed at `7b3d634`
  ([run](https://github.com/k2patel/petika/actions/runs/39073875417)).
- [x] Homelab LoadBalancer deployment, Gitea source mirror and image build,
  and ciphertext-only private Git replication; synthetic round-trip verified.
- [x] Reverse-proxy guide and configurable HTTP/HTTPS listeners.

Further hardening remains: exhaustive power-loss fault injection, independent cryptographic
review, multi-device trust-conflict merging UX, and identity replacement UI. The identity
replacement API already exists; it is intentionally separate from enrollment retry.

## Security alignment implementation priority

The [security and compliance alignment plan](security-alignment-plan.md) defines a
common high-assurance target for every deployment. Its statuses describe remaining
assessment work; completed experimental features above are not compliance claims.

- [ ] Phase 0: threat model, exact standards/control mappings, owners and evidence register.
- [ ] Phase 1: secure transport defaults, account-password migration, passkeys/MFA and sessions.
- [ ] Phase 2: key custody, device lifecycle, rotation, migration and FIPS feasibility.
- [ ] Phase 3: explicit personal, trusted-person and organization recovery policies.
- [ ] Phase 4: independently retained audit events, alerts, incident response and real backup drills.
- [ ] Phase 5: signed releases, SBOM/provenance, update verification and privacy controls.
- [ ] Phase 6: independent assessment, remediation/retest and scoped assurance evidence.

Start Phase 0 and transport/authentication work first; begin FIPS feasibility in
parallel. Feature backlog items remain open but do not replace these security gates.

## Remaining backlog

- [x] Draft per-entry format, atomic index/entry transactions, migration/rollback
  constraints and [acceptance matrix](testing/encrypted-entry-format.md). Review and
  execution remain pending; no new-format vaults are enabled.
- [x] Off-by-default entry/index cryptographic primitive prototype, explicit
  recovery wrapper, strict context/limits, and independent libsodium/Python vectors
  ([scope and remaining gates](research/entry-format-prototype.md)).
- [x] Opt-in identity-authorized epoch checkpoints, explicit authority handover,
  active-wrapper binding and entry-root recipient packages in both existing profiles
  ([trust model and pending integration](research/entry-checkpoints.md)).
- [ ] Implement API-authoritative Git-backed encrypted-entry sync: all managed
  clients use revision-checked API writes; Petika is the sole Git writer, with
  on-change/scheduled/manual replication, encrypted folder index and per-entry
  updates. No normal two-way Git merging ([design proposal](research/git-vault-sync.md)).

- [x] Rust CLI `show` with local unlock, interactive TOTP expiry, encrypted TOTP setup,
  password-store-style aliases, and non-secret `~/.petikarc` defaults.
- [x] Live CLI `show --collection` via the authenticated API with local passphrase
  unlock and no vault cache or offline fallback.
- [x] Managed CLI reads/mutations, live recipient-identity unlock, revision/epoch/
  membership checks, and encrypted drafts for rejected or uncertain saves.

- [x] Experimental Chromium toolbar login/TOTP filling with local WASM and per-fill
  origin, permission, session and document checks ([preview](../clients/extension/README.md)).
- [x] Chromium toolbar password generation, encrypted save before explicit new-password
  filling, existing-login preservation and concurrent-write protection.
- [x] Opt-in, document-bound inline signup launcher with expiry and trusted-popup
  generation; website scripts receive no suggestion or vault data.
- [x] Explicit split TOTP fill for complete six/eight-box forms, with leading-zero
  preservation and rejection of incomplete, ambiguous or cross-origin groups.
- [x] Generic Chromium preview server onboarding with optional host access and
  local session isolation on server changes; pinned builds remain available.
- [ ] Chromium/Firefox release extensions with automatic inline suggestions and saved-login selection, broader login/TOTP filling,
  QR capture, and enforced exact-origin website permissions (see [UX requirements](settings-experience.md#password-and-totp-browser-experience)).
- [x] In-vault password suggestions, account-scoped active-client listing/revocation,
  and website-permission management, enforced by the Chromium preview before filling.
- [ ] iOS/Android apps, desktop native messaging, and configurable biometric unlock.
- [ ] Full GPG key creation/export/expiry/revocation UI.
- [ ] OTP QR scanning.
- [ ] Optional OIDC, account MFA/passkeys, account recovery, and audit trails.
- [ ] OS-backed CLI credential storage and private-CA trust configuration.
- [ ] Individual selected-item sharing semantics beyond existing collection sharing.
- [x] Offline full-backup integrity/restore tooling, authenticated historical Git recovery,
  retention runbook, and synthetic clean-directory recovery drill in both modes.
- [x] Isolated cross-node Kubernetes recovery drill: original synthetic PVC/client removed,
  full backup restored to a fresh PVC, both rotated encryption modes verified, test resources
  cleaned up ([2026-10-18 result](testing/kubernetes-recovery-2026-10-18.json)).
- [x] User/operator S3 and SSH profiles, user-scoped read-only backup API keys,
  server-stored encrypted credentials, scheduled S3/SSH push jobs,
  and independent recovery tools with verified downloads (see [guide](offsite-backups.md)).
- [ ] Configure independent off-site retained storage and validate recovery after loss of the
  primary storage system; measure production recovery objectives.
- [ ] Independent security review, accessibility review, native-platform validation,
  and real-cluster deployment hardening.
- [ ] Simplified favicon.

Platform stacks, supported OS versions, recovery objectives, and later feature ordering
remain open. See [requirements](requirements.md), [architecture](architecture.md), and
[recovery](recovery.md) for constraints.

- [x] Experimental decrypted-index validation, adjacent-head continuity, exact live
  object coverage and atomic native checkpoint storage ([details](research/entry-index.md)).
- [x] Integrate bounded history catch-up and checkpoint persistence into the native
  CLI; test process-crash boundaries before API migration.

- [x] Independent head-digest vectors, bounded same-epoch history verification and
  atomic catch-up pin updates; injected atomic-write boundary failures.
- [x] Experimental content-preserving rotation verification, including every live
  payload, folder and tombstone; require it for persisted epoch advancement.
- [x] Experimental recipient-bound handoff with independent confirmation and
  no-overwrite checkpoint initialization ([details](research/entry-handoff.md)).
- [ ] Add handoff UI and complete platform validation before enabling per-entry
  transactions by default; native history sync and process-exit tests are implemented.

- [x] Experimental bounded history wire contract, server page builder and native
  durable response acceptance ([details](research/entry-history-transport.md)).
- [x] Implement isolated committed entry journal/CAS, authorized experimental
  HTTP history routes and bounded CLI sync transport.

### Experimental entry implementation progress

The core migration preservation verifier now covers exact legacy names/fields,
fresh epoch context and explicit profile continuity, with Standard/Hybrid fixtures.
It is a pre-cutover gate only; source CAS, recipient recovery checks and atomic
format switching remain unimplemented.

The gated implementation now covers the journal/CAS, authenticated HTTP history,
native CLI sync and drafts, server-only Git replication, recipient unlock, and
atomic epoch transactions. CLI rotation staging/review/submission and explicit
adjacent epoch acceptance are implemented; see the [transport contract](research/entry-history-transport.md).
The broader integration/release gates above remain open for handoff UI,
migration/cutover, complete restore, compatibility and physical durability testing.
