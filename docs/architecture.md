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

Group members currently share a collection passphrase out of band. Automatic per-user
group-key delivery is the [next milestone](roadmap.md). Server administrators can manage
membership but do not automatically receive collection decryption keys. The core now
implements local recipient identity generation, encrypted storage, and pinned recovery;
verified contact storage, enrollment APIs, and package delivery remain pending.

## Remaining design gates

The [group-key delivery proposal](decisions/0002-per-user-group-key-delivery.md) defines
recipient enrollment, identity verification, packages, recovery, and migration boundaries.
Validate protocol encodings and dependencies before implementation integration; fresh-key
rotation still needs its own implementation decision. Keep account
login separate from decryption authorization. Preserve standard and experimental hybrid
mode semantics without silently downgrading protection.

Planned extensions use native messaging; mobile clients need platform autofill and
biometric bindings. Platform packaging must preserve the no-npm requirement.

A revoked user/device may retain downloaded ciphertext, keys, and plaintext. Git history
retains old ciphertext. Rotation cannot erase passwords already disclosed. The server's
revision checks do not establish rollback resistance against a malicious server or a
restored old data directory.

Record architecture decisions with rationale and validation criteria before relying on
them in code. See the [local encryption decision](decisions/0001-local-encryption.md).
