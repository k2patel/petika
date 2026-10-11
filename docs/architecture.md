# Architecture

## Current boundaries

| Component | Purpose | Current state |
| --- | --- | --- |
| `petika-core` | Shared domain, encryption, and sync logic | Status constant only |
| `petika` | User-facing Rust CLI | Help and version only |
| `petika-server` | Self-hosted API | Fails explicitly; opens no listener |
| `petika-desktop` | Native messaging and platform authentication | Library placeholder |
| Browser/mobile clients | Autofill and interactive password management | Documentation only |

All packages have `publish = false` until the first release is ready. No external Rust
dependencies are present. Public code exposes only foundation status; no vault format,
API protocol, or cryptographic compatibility guarantee exists yet.

## Proposed direction, not a finalized protocol

Clients encrypt/decrypt locally using a shared Rust core. A central API authenticates
devices and synchronizes encrypted records. The Rust CLI is a first-class client.
Browser extensions communicate with a desktop helper using native messaging. Mobile
clients need platform bindings for biometrics and autofill. Browser glue may require
JavaScript; it must not introduce npm tooling or an npm runtime dependency.

If API-authoritative sync is selected, accepted revisions feed a one-way encrypted Git
mirror. Stale edits to the same record produce explicit conflicts. Local offline edits
queue for synchronization. Git edits do not automatically override API records.

## Design gates

Before implementing secret storage, document and review the threat model, cryptographic
library choices, authenticated record format, key wrapping, recovery, enrollment and
revocation, and migration/versioning rules. Use established cryptographic primitives;
do not invent a cipher or equate server login with decryption authorization.

A revoked device may retain already-downloaded records and keys. Git history also
retains old ciphertext. Rotation cannot retroactively erase disclosed passwords.
Choose sharing and recovery designs with these limits explicit.

Record each accepted architecture decision with rationale and validation criteria in
this directory before relying on it in code.
