# Git-authoritative encrypted vault synchronization

The [browser/strict policy update](../browser-passkeys.md) permits browser UV
(biometrics or PIN) for browser-policy vaults. Strict biometric requirements below
apply to the strict policy. Browser API-vault tests do not complete Git-authority gates.

Status: architecture direction updated 2026-10-31; implementation pending.
[ADR 0006](../decisions/0006-git-authoritative-sync.md) replaces the former
API-authoritative, sole-server-writer target. Existing API/mirror code remains implemented
behavior and is not automatically converted. No production deployment changed.

## Target workflow

On request, and before online show/edit, fetch from the configured private Git data
repository. Verify missing signed history from the last independently trusted checkpoint.
Show decrypts the requested data in client memory. Edit retains the fetched base,
decrypts/edits in memory, encrypts changed entries with fresh nonces and promptly submits
a candidate against that exact base. The destination atomically checks and updates its
head. Git acceptance, not a local draft or API enqueue acknowledgement, commits sync.

If a competing push wins, discard the obsolete submission, preserve the user's encrypted
draft, fetch and verify, review/re-edit, and try a fresh candidate. No automatic ciphertext
merge/rebase or force update. Bound retries. For a lost response, reconcile operation ID,
candidate digest and authenticated history first: a push may already have succeeded.

```mermaid
sequenceDiagram
    participant C as Device
    participant P as Petika auth / optional gateway
    participant G as Any compatible Git host
    C->>P: Account password plus one authorized device key
    P-->>C: Scoped temporary sync access
    C->>G: Fetch missing objects (direct or through gateway)
    G-->>C: Encrypted objects and signed history
    Note over C: Verify pin, decrypt/edit in memory, encrypt candidate
    C->>G: Publish candidate conditional on fetched head
    alt Head unchanged and publication authorized
        G-->>C: Accepted
        Note over C: Verify acceptance and durably advance pin
    else Another writer advanced head
        G-->>C: Conflict
        Note over C: Keep encrypted draft; fetch, review/re-edit, retry
    end
```

## Delta storage and host independence

One encrypted object per entry, opaque IDs, encrypted index/folders, authenticated
tombstones and signed head metadata. Unchanged objects retain their exact bytes. Updates
transfer missing objects; fresh ciphertext need not compress into small binary patches.
Initial sync, migration and rotation may be large. Metadata sizes/timing remain visible.

Use standard SSH or HTTPS Git transport. Host APIs are optional adapters, not a required
common API. Host capability checks cover conditional updates, permissions and credential
expiry. An arbitrary Petika-issued token is not automatically accepted by an external
host. A Petika gateway can provide temporary client access while protecting the upstream
credential; direct access requires compatible host-issued tokens or trusted SSH certificates.
Browser transport/CORS and SSH compatibility require explicit adapters or a gateway.

## Authentication, authorization and recovery

Online access requires an account password plus any one active enrolled device key
authorized for that vault. Each device normally holds an independent key. Each allowed
key opens its own encrypted package for the same vault epoch secret, which encrypts and
decrypts entries. All keys are not required together. An authorized client creates these
packages; password knowledge alone cannot grant a new key vault access. Temporary Git
credentials are transport access, independent of the vault keys. Biometric unlock protects
local device key use. Account password reset cannot recover lost vault keys. Provisioned
keys can decrypt retained ciphertext offline; server participation in every decrypt is
a separate, undecided cryptographic policy.

Device registration requires biometric-only per-action protection of generated device
keys. Every reveal/copy/autofill/edit/export or secret-decrypting operation requires fresh
approval; strings, PINs and cached approvals cannot substitute. Web QR pairing starts an expiring session; the new device
generates its keys, and an existing authority explicitly confirms its fingerprint and
verifies the two-key enrollment proof. The QR contains no vault/private key and does not
authorize admission by itself. [Exact flow](../decisions/0006-git-authoritative-sync.md#registration-methods-and-qr-device-enrollment).

Repo readers can obtain its history across branches; branches are not vault ACLs. Shared
vault permissions require repository separation or a gateway, plus verifiable writer,
membership/device and epoch policy. Publication and revocation need atomic ordering.
Git hashes alone do not authenticate vault policy or prevent rollback. Retain independent
pins and recovery keys. Token revocation cannot erase already downloaded secrets.

Online refresh failure is explicit; cached viewing is a separate offline choice. Only
ciphertext is persisted in caches/drafts/Git. Git history is not a substitute for account,
device authority, recovery kits and newest-pin backups. Exact formats and migration remain
review gates in ADR 0006.

## Existing implementation to reuse

- Default managed API: revision-checked encrypted snapshots, preserved conflict drafts,
  serialized local Git mirrors and configurable outbound SSH/HTTPS copies.
- Experimental entry feature: per-entry ciphertext, encrypted index, bounded verified
  history, atomic journal transactions, deletion/rotation, encrypted CLI drafts and
  receipt reconciliation, plus ordered outbound Git replication.
- Experimental device feature: separate recipient identities, signed rosters, two-key
  enrollment proofs, native publication journal and gated authenticated account API.

These are foundations, not a completed Git-authoritative client. See the
[entry transport contract](entry-history-transport.md) and [device API](../device-account-api.md).

## Implementation order

The [ordered work plan](../implementation-plan-git-biometric.md) now supplies package
dependencies and completion criteria. First prove persistent per-action biometric custody
and the native operation broker (B01–B03); then execute the Git work below.


1. Isolated single-vault/two-client prototype using a private local bare remote; test
   atomic races, on-demand refresh, fresh re-edit candidates and uncertain acknowledgements.
2. Freeze signed Git tree/ref, authorization, operation-ID, receipt and pin-persistence
   contracts with independent vectors. Test ciphertext-only storage and object reuse.
3. Add native SSH/HTTPS adapters, password-plus-device-key authentication/gateway capabilities and actual host tests.
4. Connect durable device custody and interactive conflict review, then browser transport.
5. Validate shared-vault authorization/revocation/rotation, recovery and explicit per-vault
   migration. Keep old stores and backups; enforce one authority after cutover.

No code, runtime flag, migration or deployment is enabled by this document update.
