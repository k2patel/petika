# Architecture

## Current boundaries

| Component | Purpose | Current state |
| --- | --- | --- |
| `petika-core` | Shared records, encryption, local storage | Standard/hybrid envelopes, record operations, local recipient identities/recovery, atomic native persistence |
| `petika` | Rust CLI | Offline password management, GPG import, managed login, encrypted collection pull/push |
| `petika-server` | Self-hosted API and web hosting | Accounts, permissions, provisioning, revision checks, snapshot journals, Git mirrors |
| `petika-web` and `clients/web` | Browser password manager | Rust/WASM encryption worker and JavaScript/CSS interface |
| `petika-desktop` | Native messaging and platform authentication | Library placeholder |
| Browser extensions/mobile apps | Platform autofill and biometric unlock | Not implemented |

Packages remain unpublished (`publish = false`). Cargo dependencies and the lockfile
are present. Storage and API formats are versioned but experimental; there is no stable
compatibility guarantee. See [schema upgrades](schema.md).

## Implemented data flow

Clients encrypt/decrypt locally using the shared Rust core. Server authentication is
separate from collection unlocking. The API authorizes personal/group collection access
and accepts whole encrypted snapshots using compare-and-swap revisions. Stale writes
are rejected; clients retain local changes for explicit resolution. There is no automatic
per-record merge. The CLI uses explicit pull/push; the web client saves encrypted drafts
and attempts synchronization.

Accepted snapshots are journaled and mirrored to separate local Git repositories. Git
is a one-way recovery mirror, not a writable synchronization peer. Remote Git replication
is an operator task. Accounts and memberships are server metadata outside the mirror.

Legacy groups use a collection passphrase out of band. Explicitly migrated groups use
verified per-user encrypted packages; enrollment, trust verification, delivery, and fresh-key
rotation are implemented in CLI/web. Administrators can manage membership but do not
automatically receive decryption keys. See [group access](group-access.md).

## Remaining design gates

The [group-key delivery design](decisions/0002-per-user-group-key-delivery.md) and
[wire format](key-package-format.md) define enrollment, packages, recovery, migration,
and explicit rotation. Keep account login separate from decryption authorization and
preserve Standard/Hybrid mode semantics. Independent cryptographic review and exhaustive
crash/concurrency hardening remain necessary before a production-readiness claim.

Planned extensions use native messaging; mobile clients need platform autofill and
biometric bindings. Platform packaging must preserve the no-npm requirement.

A revoked user/device may retain downloaded ciphertext, keys, and plaintext. Git history
retains old ciphertext. Rotation cannot erase passwords already disclosed. The server's
revision checks do not establish rollback resistance against a malicious server or a
restored old data directory.

Record architecture decisions with rationale and validation criteria before relying on
them in code. See the [local encryption decision](decisions/0001-local-encryption.md).
